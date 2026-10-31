#!/usr/bin/env python3
"""
wifi_scanner.py — Escáner de redes Wi-Fi para Windows (usa netsh)

Funciones:
  · Escaneo por BSSID (cada punto de acceso es una fila, no solo cada SSID)
  · Compatible con Windows en español e inglés
  · Historial persistente (JSON Lines, con rotación automática)
  · Exportación a JSON / CSV (escritura atómica, CSV listo para Excel)
  · Monitor continuo con detección de redes nuevas, perdidas y cambios de señal
  · Análisis de canales con recomendación basada en interferencia real

Ejemplos:
  python wifi_scanner.py
  python wifi_scanner.py --canales --banda 2.4
  python wifi_scanner.py --solo-seguras --min-senal 50 --ordenar canal
  python wifi_scanner.py --exportar-csv redes.csv --csv-sep ";"
  python wifi_scanner.py --monitor --intervalo 15
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import unicodedata
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("wifi_scanner")

# ──────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────
APP_DIR = Path.home() / ".wifi_scanner"
HISTORIAL_FILE = APP_DIR / "historial.jsonl"
MAX_ESCANEOS_HISTORIAL = 500
NETSH_TIMEOUT = 20  # segundos
SSID_OCULTO = "[Red Oculta]"

COLORES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "verde": "\033[92m",
    "amarillo": "\033[93m",
    "rojo": "\033[91m",
    "cyan": "\033[96m",
    "gris": "\033[90m",
}


# ──────────────────────────────────────────────
# Utilidades
# ──────────────────────────────────────────────
def _normalizar(texto: str) -> str:
    """Minúsculas, sin tildes y con espacios colapsados (para comparar claves de netsh)."""
    sin_tildes = "".join(
        c for c in unicodedata.normalize("NFD", texto) if unicodedata.category(c) != "Mn"
    )
    return re.sub(r"\s+", " ", sin_tildes).strip().lower()


def _a_int(texto: str) -> Optional[int]:
    digitos = re.sub(r"\D", "", texto)
    return int(digitos) if digitos else None


def _recortar(texto: str, largo: int) -> str:
    return texto if len(texto) <= largo else texto[: largo - 1] + "…"


def _primera_linea(texto: str) -> str:
    return next((l.strip() for l in texto.splitlines() if l.strip()), "")


def _codepage_oem() -> str:
    """netsh imprime en la página de códigos OEM de la consola (cp850, cp437…), no en UTF-8."""
    try:
        import ctypes

        return f"cp{ctypes.windll.kernel32.GetOEMCP()}"  # type: ignore[attr-defined]
    except Exception:
        return "utf-8"


def _escribir_atomico(path: Path | str, contenido: str, encoding: str = "utf-8", newline: Optional[str] = None):
    """Escribe a un temporal y reemplaza el destino, para no dejar archivos a medias."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as f:
            f.write(contenido)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _habilitar_ansi() -> bool:
    """Activa secuencias ANSI en la consola de Windows 10+. Devuelve False si no se pudo."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        modo = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(modo)):
            return False
        return bool(kernel32.SetConsoleMode(handle, modo.value | 0x0004))  # VT processing
    except Exception:
        return False


def _configurar_consola(usar_color: bool):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass
    color_ok = (
        usar_color
        and sys.stdout.isatty()
        and not os.environ.get("NO_COLOR")
        and _habilitar_ansi()
    )
    if not color_ok:
        for k in COLORES:
            COLORES[k] = ""


# ──────────────────────────────────────────────
# Modelo de datos (una fila = un punto de acceso / BSSID)
# ──────────────────────────────────────────────
_RE_GHZ = re.compile(r"(\d+(?:[.,]\d+)?)\s*ghz", re.IGNORECASE)


@dataclass
class RedWiFi:
    ssid: str
    bssid: str = "N/A"
    señal: int = 0                    # porcentaje 0-100 (calidad según Windows)
    canal: Optional[int] = None
    seguridad: str = "N/A"            # autenticación según netsh (WPA2-Personal, etc.)
    cifrado: str = "N/A"              # CCMP, TKIP, WEP, Ninguno…
    tipo_radio: str = "N/A"           # 802.11n / ac / ax
    banda: str = ""                   # "2.4 GHz" / "5 GHz" / "6 GHz"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def __post_init__(self):
        self.banda = self._normalizar_banda(self.banda, self.canal)

    @staticmethod
    def _normalizar_banda(banda: str, canal: Optional[int]) -> str:
        """Usa la banda informada por netsh si existe; si no, la infiere del canal."""
        m = _RE_GHZ.search(banda or "")
        if m:
            return f"{m.group(1).replace(',', '.')} GHz"
        if canal is None:
            return "Desconocida"
        return "2.4 GHz" if canal <= 14 else "5 GHz"

    @property
    def calidad(self) -> str:
        if self.señal >= 80:
            return "Excelente"
        if self.señal >= 60:
            return "Buena"
        if self.señal >= 40:
            return "Regular"
        return "Débil"

    @property
    def dbm(self) -> int:
        """Aproximación estándar de Windows: dBm = porcentaje/2 − 100."""
        return round(self.señal / 2 - 100)

    @property
    def nivel_seguridad(self) -> str:
        auth, cif = self.seguridad.upper(), self.cifrado.upper()
        if "WPA3" in auth or "SAE" in auth:
            return "WPA3"
        if "WPA2" in auth:
            return "WPA2"
        if "WPA" in auth:
            return "WPA"
        if "WEP" in auth or "WEP" in cif:   # WEP aparece como Autenticación "Open" + Cifrado "WEP"
            return "WEP"
        if "OWE" in auth or "ENHANCED" in auth:
            return "OWE"
        if "OPEN" in auth or "ABIERT" in auth:
            return "Abierta"
        return "Desconocida"

    @property
    def es_segura(self) -> bool:
        return self.nivel_seguridad in ("WPA2", "WPA3", "OWE")

    @property
    def es_debil(self) -> bool:
        """Cifrado obsoleto: WEP y WPA (v1) se consideran inseguros."""
        return self.nivel_seguridad in ("WEP", "WPA")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["calidad"] = self.calidad
        d["dbm"] = self.dbm
        d["nivel_seguridad"] = self.nivel_seguridad
        d["es_segura"] = self.es_segura
        return d


# ──────────────────────────────────────────────
# Escáner principal
# ──────────────────────────────────────────────
class PlataformaNoSoportada(RuntimeError):
    pass


# Las claves de netsh están localizadas; se aceptan inglés y español (y tolera tildes mal decodificadas).
_RE_SSID = re.compile(r"^ssid\s*\d+$")
_RE_BSSID = re.compile(r"^bssid\s*\d+$")
_PATRONES_CAMPO = {
    "señal": re.compile(r"^(signal|se.{0,2}al)$"),
    "canal": re.compile(r"^(channel|canal)$"),
    "seguridad": re.compile(r"^(authentication|autenticaci.{0,3}n)$"),
    "cifrado": re.compile(r"^(encryption|cifrado)$"),
    "tipo_radio": re.compile(r"^(radio type|tipo de radio)$"),
    "banda": re.compile(r"^(band|banda)$"),
}


def _campo(clave: str) -> Optional[str]:
    for nombre, patron in _PATRONES_CAMPO.items():
        if patron.match(clave):
            return nombre
    return None


class WiFiScanner:
    """Escanea con `netsh wlan` (Windows)."""

    def __init__(self):
        if sys.platform != "win32":
            raise PlataformaNoSoportada("Este escáner requiere Windows (usa netsh).")
        self._codec = _codepage_oem()

    def _netsh(self, *args: str) -> Optional[str]:
        cmd = ["netsh", "wlan", *args]
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                timeout=NETSH_TIMEOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError:
            logger.error("'netsh' no encontrado. ¿Está ejecutando esto en Windows?")
            return None
        except subprocess.TimeoutExpired:
            logger.error("netsh no respondió en %ss.", NETSH_TIMEOUT)
            return None
        except OSError as e:
            logger.error("Error de sistema al ejecutar netsh: %s", e)
            return None

        salida = r.stdout.decode(self._codec, errors="replace")
        if r.returncode != 0:
            detalle = _primera_linea(salida) or _primera_linea(r.stderr.decode(self._codec, errors="replace"))
            logger.error("netsh retornó error (código %s): %s", r.returncode, detalle)
            return None
        return salida

    def escanear(self) -> list[RedWiFi]:
        """Devuelve los puntos de acceso visibles, ordenados por señal."""
        salida = self._netsh("show", "networks", "mode=bssid")
        if salida is None:
            return []
        redes = self._parsear(salida)
        if not redes:
            logger.warning("No se detectaron redes. Salida de netsh: %s", _primera_linea(salida) or "(vacía)")
            logger.warning(
                "Verifique que el Wi-Fi esté activado y que el servicio WLAN esté corriendo. "
                "En Windows 11 el escaneo puede requerir tener habilitados los Servicios de ubicación."
            )
        return redes

    def bssid_conectado(self) -> Optional[str]:
        """BSSID del punto de acceso al que está conectado el equipo (None si no hay conexión)."""
        salida = self._netsh("show", "interfaces")
        if not salida:
            return None
        for linea in salida.splitlines():
            if ":" not in linea:
                continue
            clave, valor = linea.split(":", 1)
            if _normalizar(clave) in ("bssid", "ap bssid"):
                return valor.strip().lower() or None
        return None

    @staticmethod
    def _parsear(texto: str) -> list[RedWiFi]:
        """
        Estructura de `netsh wlan show networks mode=bssid`:
            SSID n : nombre          ← autenticación y cifrado van a nivel SSID
            BSSID m : mac            ← señal, canal, banda y radio van por cada BSSID
        Genera una RedWiFi por cada BSSID (antes se perdían todos menos el último de cada SSID).
        """
        redes: list[RedWiFi] = []
        ssid, auth, cifrado = SSID_OCULTO, "N/A", "N/A"
        ap: Optional[dict] = None

        for linea in texto.splitlines():
            if ":" not in linea:
                continue
            clave, valor = linea.split(":", 1)
            clave, valor = _normalizar(clave), valor.strip()

            if _RE_SSID.match(clave):
                if ap:
                    redes.append(RedWiFi(**ap))
                    ap = None
                ssid = valor or SSID_OCULTO
                auth = cifrado = "N/A"
            elif _RE_BSSID.match(clave):
                if ap:
                    redes.append(RedWiFi(**ap))
                ap = {"ssid": ssid, "bssid": valor.lower(), "seguridad": auth, "cifrado": cifrado}
            else:
                campo = _campo(clave)
                if campo is None:
                    continue
                if ap is None:
                    if campo == "seguridad":
                        auth = valor
                    elif campo == "cifrado":
                        cifrado = valor
                elif campo == "señal":
                    ap[campo] = _a_int(valor) or 0
                elif campo == "canal":
                    ap[campo] = _a_int(valor)
                else:
                    ap[campo] = valor

        if ap:
            redes.append(RedWiFi(**ap))

        return sorted(redes, key=lambda r: r.señal, reverse=True)


# ──────────────────────────────────────────────
# Filtros y orden
# ──────────────────────────────────────────────
@dataclass
class Filtros:
    ssid: Optional[str] = None
    solo_seguras: bool = False
    banda: Optional[str] = None      # "2.4 GHz" / "5 GHz" / "6 GHz"
    min_senal: int = 0
    ordenar: str = "senal"           # senal | ssid | canal

    def aplicar(self, redes: list[RedWiFi]) -> list[RedWiFi]:
        res = redes
        if self.ssid:
            txt = self.ssid.lower()
            res = [r for r in res if txt in r.ssid.lower()]
        if self.solo_seguras:
            res = [r for r in res if r.es_segura]
        if self.banda:
            res = [r for r in res if r.banda == self.banda]
        if self.min_senal:
            res = [r for r in res if r.señal >= self.min_senal]

        claves = {
            "senal": lambda r: -r.señal,
            "ssid": lambda r: (r.ssid.lower(), -r.señal),
            "canal": lambda r: (r.canal if r.canal is not None else 9999, -r.señal),
        }
        return sorted(res, key=claves[self.ordenar])


# ──────────────────────────────────────────────
# Historial persistente (JSON Lines: append-only, sin reescribir todo en cada escaneo)
# ──────────────────────────────────────────────
class Historial:
    def __init__(self, path: Path | str = HISTORIAL_FILE, maximo: int = MAX_ESCANEOS_HISTORIAL):
        self.path = Path(path)
        self.maximo = maximo
        self._n: Optional[int] = None

    def _contar(self) -> int:
        if not self.path.exists():
            return 0
        with self.path.open("r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)

    def guardar_escaneo(self, redes: list[RedWiFi]):
        entrada = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "redes": [r.to_dict() for r in redes],
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self._n is None:
                self._n = self._contar()
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
            self._n += 1
            if self._n > self.maximo + max(10, self.maximo // 10):
                self._recortar()
            logger.debug("Historial guardado en '%s' (%s escaneos).", self.path, self._n)
        except OSError as e:
            logger.error("No se pudo guardar el historial: %s", e)

    def _recortar(self):
        with self.path.open("r", encoding="utf-8", errors="ignore") as f:
            ultimas = deque(f, maxlen=self.maximo)
        _escribir_atomico(self.path, "".join(ultimas))
        self._n = len(ultimas)

    def listar_escaneos(self, ultimos: int = 20):
        entradas: list[tuple[str, int]] = []
        if self.path.exists():
            with self.path.open("r", encoding="utf-8", errors="ignore") as f:
                for linea in f:
                    try:
                        e = json.loads(linea)
                        entradas.append((e["timestamp"], len(e["redes"])))
                    except (json.JSONDecodeError, KeyError, TypeError):
                        continue  # línea corrupta: se ignora

        total = len(entradas)
        print(f"\n📂 Historial: {total} escaneos  ({self.path})")
        if not total:
            return
        inicio = max(0, total - ultimos)
        if inicio:
            print(f"  … mostrando los últimos {ultimos}")
        for i, (ts, n) in enumerate(entradas[inicio:], inicio + 1):
            print(f"  {i:>4}. {ts}  —  {n} redes")


# ──────────────────────────────────────────────
# Exportación
# ──────────────────────────────────────────────
class Exportador:

    @staticmethod
    def a_json(redes: list[RedWiFi], archivo: str = "redes.json") -> bool:
        if not redes:
            logger.warning("No hay redes para exportar a JSON.")
            return False
        try:
            _escribir_atomico(archivo, json.dumps([r.to_dict() for r in redes], indent=2, ensure_ascii=False))
        except OSError as e:
            logger.error("No se pudo exportar a '%s': %s", archivo, e)
            return False
        logger.info("Exportado JSON → %s", archivo)
        return True

    @staticmethod
    def a_csv(redes: list[RedWiFi], archivo: str = "redes.csv", sep: str = ",") -> bool:
        """CSV con BOM UTF-8 para que Excel muestre bien las tildes y la ñ."""
        if not redes:
            logger.warning("No hay redes para exportar a CSV.")
            return False
        filas = [r.to_dict() for r in redes]
        buf = io.StringIO(newline="")
        writer = csv.DictWriter(buf, fieldnames=list(filas[0]), delimiter=sep)
        writer.writeheader()
        writer.writerows(filas)
        try:
            _escribir_atomico(archivo, buf.getvalue(), encoding="utf-8-sig", newline="")
        except PermissionError:
            logger.error("No se pudo escribir '%s'. ¿Está abierto en Excel?", archivo)
            return False
        except OSError as e:
            logger.error("No se pudo exportar a '%s': %s", archivo, e)
            return False
        logger.info("Exportado CSV  → %s", archivo)
        return True


# ──────────────────────────────────────────────
# Análisis de canales
# ──────────────────────────────────────────────
class AnalizadorCanales:
    """
    Agrupa por banda (el canal 1 de 2.4 GHz no es el canal 1 de 6 GHz) y recomienda
    el canal con menos interferencia ponderada por intensidad de señal.
    Nota: si analiza su propio router, su red también cuenta como ocupación.
    """

    CANDIDATOS = {
        "2.4 GHz": (1, 6, 11),
        "5 GHz": (36, 40, 44, 48, 149, 153, 157, 161),  # sin canales DFS
    }

    @staticmethod
    def analizar(redes: list[RedWiFi]) -> dict[str, dict[int, list[RedWiFi]]]:
        por_banda: dict[str, dict[int, list[RedWiFi]]] = defaultdict(lambda: defaultdict(list))
        for r in redes:
            if r.canal is not None:
                por_banda[r.banda][r.canal].append(r)
        return {b: dict(c) for b, c in por_banda.items()}

    @staticmethod
    def _interferencia(redes: list[RedWiFi], banda: str, canal: int) -> float:
        total = 0.0
        for r in redes:
            if r.banda != banda or r.canal is None:
                continue
            if banda == "2.4 GHz":
                # Canales de 20 MHz separados por menos de 5 se solapan parcialmente.
                sep = abs(r.canal - canal)
                if sep < 5:
                    total += r.señal * (1 - sep / 5)
            elif r.canal == canal:
                total += r.señal
        return total

    @staticmethod
    def recomendar_canal(redes: list[RedWiFi], banda: str = "2.4 GHz") -> Optional[int]:
        candidatos = AnalizadorCanales.CANDIDATOS.get(banda)
        if not candidatos:
            return None
        return min(candidatos, key=lambda c: AnalizadorCanales._interferencia(redes, banda, c))

    @staticmethod
    def mostrar_mapa(redes: list[RedWiFi]):
        uso = AnalizadorCanales.analizar(redes)
        if not uso:
            print("\n📊 Mapa de canales: sin datos.")
            return
        print("\n📊 Mapa de canales:")
        for banda in sorted(uso):
            print(f"\n  {COLORES['bold']}{banda}{COLORES['reset']}")
            for canal in sorted(uso[banda]):
                aps = uso[banda][canal]
                ssids = ", ".join(sorted({r.ssid for r in aps}))
                barra = "█" * min(len(aps), 12)
                print(f"    Canal {canal:>3} {barra:<12} {len(aps):>2} AP  {_recortar(ssids, 60)}")
            recom = AnalizadorCanales.recomendar_canal(redes, banda)
            if recom is not None:
                print(f"    💡 Canal recomendado: {recom}")


# ──────────────────────────────────────────────
# Visualización
# ──────────────────────────────────────────────
def _color_calidad(calidad: str) -> str:
    return {
        "Excelente": COLORES["verde"],
        "Buena": COLORES["cyan"],
        "Regular": COLORES["amarillo"],
        "Débil": COLORES["rojo"],
    }[calidad]


class Visualizador:

    @staticmethod
    def mostrar_tabla(redes: list[RedWiFi], conectado: Optional[str] = None, mostrar_bssid: bool = False):
        C = COLORES
        ancho = 106 if mostrar_bssid else 86
        sep = "─" * ancho

        print(f"\n{C['bold']}{'📡 REDES WI-FI':^{ancho}}{C['reset']}")
        print(f"{C['gris']}{datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^{ancho}}{C['reset']}")
        print(sep)
        cab = f"{'#':>3}  {'SSID':<26} "
        if mostrar_bssid:
            cab += f"{'BSSID':<17} "
        cab += f"{'Señal':<15} {'Calidad':<9} {'Canal':>5} {'Banda':<7} Seguridad"
        print(cab)
        print(sep)

        hay_conectada = False
        for i, r in enumerate(redes, 1):
            col = _color_calidad(r.calidad)
            barra = "▓" * (r.señal // 10) + "░" * (10 - r.señal // 10)
            es_conectada = bool(conectado) and r.bssid == conectado
            hay_conectada |= es_conectada
            canal = r.canal if r.canal is not None else "-"
            icono = "🔒" if r.es_segura else ("🔓" if r.nivel_seguridad == "Abierta" else "⚠ ")

            fila = f"{i:>3}{'★' if es_conectada else ' '} {_recortar(r.ssid, 26):<26} "
            if mostrar_bssid:
                fila += f"{r.bssid:<17} "
            fila += (
                f"{col}{r.señal:>3}% {barra}{C['reset']} "
                f"{col}{r.calidad:<9}{C['reset']} "
                f"{canal:>5} {r.banda:<7} {icono} {r.nivel_seguridad}"
            )
            print(fila)

        print(sep)
        seguras = sum(1 for r in redes if r.es_segura)
        debiles = sum(1 for r in redes if r.es_debil)
        abiertas = sum(1 for r in redes if r.nivel_seguridad == "Abierta")
        print(
            f"  APs: {len(redes)}  |  SSIDs únicos: {len({r.ssid for r in redes})}  |  "
            f"Seguras: {seguras}  |  Débiles (WEP/WPA): {debiles}  |  Abiertas: {abiertas}"
        )
        if hay_conectada:
            print(f"  {C['gris']}★ = red a la que está conectado{C['reset']}")

        if redes:
            mejor = max(redes, key=lambda r: r.señal)
            print(
                f"\n  🏆 Mejor señal: {C['bold']}{mejor.ssid}{C['reset']} — {mejor.señal}% "
                f"({mejor.calidad}, {mejor.dbm} dBm) en canal {mejor.canal} [{mejor.banda}]"
            )


# ──────────────────────────────────────────────
# Monitor continuo
# ──────────────────────────────────────────────
class Monitor:

    def __init__(
        self,
        scanner: WiFiScanner,
        historial: Optional[Historial],
        filtros: Filtros,
        intervalo: int = 10,
        mostrar_bssid: bool = False,
    ):
        self.scanner = scanner
        self.historial = historial
        self.filtros = filtros
        self.intervalo = intervalo
        self.mostrar_bssid = mostrar_bssid

    def iniciar(self, ciclos: int = 0):
        """Escanea indefinidamente (ciclos=0) o N veces."""
        print(f"\n🔄 Monitor iniciado — intervalo: {self.intervalo}s  (Ctrl+C para detener)\n")
        previo: Optional[dict[str, RedWiFi]] = None
        count = 0
        try:
            while True:
                todas = self.scanner.escanear()
                if todas:
                    visibles = self.filtros.aplicar(todas)
                    actual = {r.bssid: r for r in visibles}
                    os.system("cls" if os.name == "nt" else "clear")
                    Visualizador.mostrar_tabla(visibles, self.scanner.bssid_conectado(), self.mostrar_bssid)
                    if previo is not None:
                        self._mostrar_cambios(previo, actual)
                    if self.historial:
                        self.historial.guardar_escaneo(todas)
                    previo = actual
                else:
                    logger.warning("Escaneo sin resultados; se reintentará.")

                count += 1
                if ciclos and count >= ciclos:
                    break
                time.sleep(self.intervalo)
        except KeyboardInterrupt:
            print("\n⛔ Monitor detenido.")

    @staticmethod
    def _mostrar_cambios(previo: dict[str, RedWiFi], actual: dict[str, RedWiFi], umbral: int = 10):
        C = COLORES
        nuevas = [r for b, r in actual.items() if b not in previo]
        perdidas = [r for b, r in previo.items() if b not in actual]
        variaciones = [
            (r, previo[b].señal)
            for b, r in actual.items()
            if b in previo and abs(r.señal - previo[b].señal) >= umbral
        ]

        print(f"\n  {C['bold']}Cambios desde el escaneo anterior:{C['reset']}")
        if not (nuevas or perdidas or variaciones):
            print(f"  {C['gris']}Sin cambios relevantes.{C['reset']}")
            return

        def imprimir(items, formato, color, limite=5):
            for it in items[:limite]:
                print(f"  {color}{formato(it)}{C['reset']}")
            if len(items) > limite:
                print(f"  {C['gris']}… y {len(items) - limite} más{C['reset']}")

        imprimir(nuevas, lambda r: f"+ {r.ssid} ({r.bssid}) — {r.señal}%", C["verde"])
        imprimir(perdidas, lambda r: f"- {r.ssid} ({r.bssid}) — última señal {r.señal}%", C["rojo"])
        imprimir(variaciones, lambda t: f"~ {t[0].ssid}: {t[1]}% → {t[0].señal}%", C["amarillo"])


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="📡 Escáner Wi-Fi avanzado para Windows",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    g = p.add_argument_group("Filtros y orden")
    g.add_argument("--filtrar-ssid", metavar="TEXTO", help="Filtrar por nombre de red (parcial)")
    g.add_argument("--solo-seguras", action="store_true", help="Mostrar solo redes WPA2/WPA3")
    g.add_argument("--banda", choices=["2.4", "5", "6"], help="Mostrar solo una banda (GHz)")
    g.add_argument("--min-senal", type=int, default=0, metavar="%", help="Señal mínima (0-100)")
    g.add_argument("--ordenar", choices=["senal", "ssid", "canal"], default="senal", help="Criterio de orden (default: senal)")
    g.add_argument("--bssid", action="store_true", help="Mostrar columna BSSID (MAC del AP)")

    g = p.add_argument_group("Análisis y exportación")
    g.add_argument("--canales", action="store_true", help="Mapa de canales y recomendación (usa todas las redes, sin filtros)")
    g.add_argument("--exportar-json", metavar="ARCHIVO", help="Exportar resultados a JSON")
    g.add_argument("--exportar-csv", metavar="ARCHIVO", help="Exportar resultados a CSV")
    g.add_argument("--csv-sep", default=",", metavar="SEP", help='Separador CSV (default: ","; use ";" para Excel en español)')

    g = p.add_argument_group("Monitor e historial")
    g.add_argument("--monitor", action="store_true", help="Modo monitor continuo")
    g.add_argument("--intervalo", type=int, default=10, metavar="SEG", help="Intervalo del monitor (default: 10)")
    g.add_argument("--ciclos", type=int, default=0, metavar="N", help="Cantidad de escaneos del monitor (0 = infinito)")
    g.add_argument("--historial", action="store_true", help="Mostrar historial de escaneos y salir")
    g.add_argument("--archivo-historial", default=str(HISTORIAL_FILE), metavar="RUTA", help=f"Ubicación del historial (default: {HISTORIAL_FILE})")
    g.add_argument("--sin-historial", action="store_true", help="No guardar este escaneo en el historial")

    g = p.add_argument_group("Salida")
    g.add_argument("--sin-color", action="store_true", help="Desactivar colores ANSI")
    g.add_argument("-v", "--verbose", action="store_true", help="Mostrar mensajes de depuración")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.intervalo < 1:
        parser.error("--intervalo debe ser >= 1")
    if not 0 <= args.min_senal <= 100:
        parser.error("--min-senal debe estar entre 0 y 100")

    _configurar_consola(usar_color=not args.sin_color)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    historial = Historial(Path(args.archivo_historial))
    if args.historial:
        historial.listar_escaneos()
        return 0

    try:
        scanner = WiFiScanner()
    except PlataformaNoSoportada as e:
        logger.error("%s", e)
        return 1

    filtros = Filtros(
        ssid=args.filtrar_ssid,
        solo_seguras=args.solo_seguras,
        banda=f"{args.banda} GHz" if args.banda else None,
        min_senal=args.min_senal,
        ordenar=args.ordenar,
    )
    guardar = None if args.sin_historial else historial

    if args.monitor:
        Monitor(scanner, guardar, filtros, args.intervalo, args.bssid).iniciar(args.ciclos)
        return 0

    logger.info("Escaneando redes Wi-Fi…")
    todas = scanner.escanear()
    redes = filtros.aplicar(todas)

    Visualizador.mostrar_tabla(redes, scanner.bssid_conectado(), args.bssid)

    if args.canales:
        AnalizadorCanales.mostrar_mapa(todas)

    if args.exportar_json:
        Exportador.a_json(redes, args.exportar_json)
    if args.exportar_csv:
        Exportador.a_csv(redes, args.exportar_csv, args.csv_sep)

    if guardar and todas:
        guardar.guardar_escaneo(todas)

    return 0 if todas else 1


if __name__ == "__main__":
    sys.exit(main())
