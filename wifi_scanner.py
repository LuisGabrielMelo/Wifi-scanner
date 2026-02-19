"""
wifi_scanner.py — Escáner de redes Wi-Fi avanzado para Windows
Módulos: escaneo, historial, exportación, monitoreo continuo, análisis de canales
"""

import subprocess
import json
import csv
import time
import os
import sys
import argparse
import logging
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from collections import defaultdict

# ──────────────────────────────────────────────
# Configuración de logging
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

HISTORIAL_FILE = Path("wifi_historial.json")

# ──────────────────────────────────────────────
# Modelo de datos
# ──────────────────────────────────────────────
@dataclass
class RedWiFi:
    ssid: str
    bssid: str = "N/A"
    señal: int = 0
    canal: str = "N/A"
    seguridad: str = "N/A"
    tipo_radio: str = "N/A"
    banda: str = "N/A"          # 2.4 GHz / 5 GHz
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def __post_init__(self):
        """Inferir banda según canal."""
        try:
            canal_num = int(self.canal)
            self.banda = "5 GHz" if canal_num > 14 else "2.4 GHz"
        except ValueError:
            self.banda = "Desconocida"

    @property
    def calidad(self) -> str:
        if self.señal >= 80:
            return "Excelente"
        elif self.señal >= 60:
            return "Buena"
        elif self.señal >= 40:
            return "Regular"
        else:
            return "Débil"

    @property
    def es_segura(self) -> bool:
        return "WPA" in self.seguridad.upper() or "WPA2" in self.seguridad.upper()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["calidad"] = self.calidad
        d["es_segura"] = self.es_segura
        return d


# ──────────────────────────────────────────────
# Escáner principal
# ──────────────────────────────────────────────
class WiFiScanner:
    """Clase principal de escaneo. Usa `netsh` en Windows."""

    def __init__(self):
        self._verificar_plataforma()

    @staticmethod
    def _verificar_plataforma():
        if sys.platform != "win32":
            logger.error("Este escáner requiere Windows (netsh).")
            sys.exit(1)

    def escanear(self) -> list[RedWiFi]:
        """Ejecuta netsh y devuelve lista de RedWiFi ordenada por señal."""
        try:
            resultado = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                encoding="utf-8",
                errors="ignore",
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"netsh retornó error (código {e.returncode}): {e}")
            return []
        except FileNotFoundError:
            logger.error("'netsh' no encontrado. ¿Está ejecutando esto en Windows?")
            return []
        except OSError as e:
            logger.error(f"Error de sistema al ejecutar netsh: {e}")
            return []
        except Exception as e:
            logger.error(f"Error inesperado al ejecutar netsh: {e}")
            return []

        return self._parsear(resultado)

    @staticmethod
    def _parsear(texto: str) -> list[RedWiFi]:
        redes: list[RedWiFi] = []
        bloque: dict = {}

        def _guardar_bloque(b: dict):
            if "ssid" in b:
                # Redes con SSID vacío son redes ocultas; etiquetarlas explícitamente
                if not b["ssid"]:
                    b["ssid"] = "[Red Oculta]"
                redes.append(RedWiFi(**b))

        def _val(l: str) -> str:
            return l.split(":", 1)[1].strip() if ":" in l else ""

        for linea in texto.splitlines():
            linea = linea.strip()
            if not linea:
                continue

            # Detectar inicio de nueva red (SSID sin número de índice)
            if linea.startswith("SSID") and not linea.startswith("BSSID"):
                # "SSID 1 : MiRed" o "SSID             : MiRed"
                _guardar_bloque(bloque)
                bloque = {"ssid": _val(linea)}
            elif linea.startswith("BSSID"):
                bloque["bssid"] = _val(linea)
            elif linea.lower().startswith("signal"):
                try:
                    bloque["señal"] = int(_val(linea).replace("%", ""))
                except ValueError:
                    bloque["señal"] = 0
            elif linea.lower().startswith("channel"):
                bloque["canal"] = _val(linea)
            elif linea.lower().startswith("authentication"):
                bloque["seguridad"] = _val(linea)
            elif linea.lower().startswith("radio type"):
                bloque["tipo_radio"] = _val(linea)

        _guardar_bloque(bloque)

        return sorted(redes, key=lambda r: r.señal, reverse=True)


# ──────────────────────────────────────────────
# Historial persistente
# ──────────────────────────────────────────────
class Historial:
    """Guarda y carga escaneos anteriores en JSON."""

    def __init__(self, path: Path = HISTORIAL_FILE):
        self.path = path
        self._data: list[dict] = self._cargar()

    def _cargar(self) -> list[dict]:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                logger.warning("Historial corrupto; se creará uno nuevo.")
        return []

    def guardar_escaneo(self, redes: list[RedWiFi]):
        entrada = {
            "timestamp": datetime.now().isoformat(),
            "redes": [r.to_dict() for r in redes],
        }
        self._data.append(entrada)
        self.path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"Historial guardado en '{self.path}' ({len(self._data)} escaneos totales).")

    def listar_escaneos(self):
        print(f"\n📂 Historial ({len(self._data)} escaneos):")
        for i, e in enumerate(self._data, 1):
            n = len(e["redes"])
            print(f"  {i}. {e['timestamp']}  —  {n} redes")


# ──────────────────────────────────────────────
# Exportación
# ──────────────────────────────────────────────
class Exportador:

    @staticmethod
    def a_json(redes: list[RedWiFi], archivo: str = "redes.json"):
        Path(archivo).write_text(
            json.dumps([r.to_dict() for r in redes], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"Exportado JSON → {archivo}")

    @staticmethod
    def a_csv(redes: list[RedWiFi], archivo: str = "redes.csv"):
        if not redes:
            return
        with open(archivo, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=redes[0].to_dict().keys())
            writer.writeheader()
            writer.writerows(r.to_dict() for r in redes)
        logger.info(f"Exportado CSV  → {archivo}")


# ──────────────────────────────────────────────
# Análisis de canales
# ──────────────────────────────────────────────
class AnalizadorCanales:

    @staticmethod
    def analizar(redes: list[RedWiFi]) -> dict[str, list[str]]:
        canales: dict[str, list[str]] = defaultdict(list)
        for r in redes:
            canales[r.canal].append(r.ssid)
        return dict(canales)

    @staticmethod
    def recomendar_canal(redes: list[RedWiFi]) -> Optional[str]:
        """Recomienda el canal 2.4 GHz menos congestionado (1, 6 o 11)."""
        canales_preferidos = ["1", "6", "11"]
        uso = AnalizadorCanales.analizar(redes)
        mejor = min(canales_preferidos, key=lambda c: len(uso.get(c, [])))
        return mejor

    @staticmethod
    def mostrar_mapa(redes: list[RedWiFi]):
        uso = AnalizadorCanales.analizar(redes)
        print("\n📊 Mapa de canales:\n")
        for canal in sorted(uso, key=lambda c: (len(c), c)):
            redes_en_canal = uso[canal]
            barra = "█" * len(redes_en_canal)
            print(f"  Canal {canal:>3} {barra} ({len(redes_en_canal)} redes): {', '.join(redes_en_canal)}")
        recom = AnalizadorCanales.recomendar_canal(redes)
        if recom:
            print(f"\n  💡 Canal recomendado para 2.4 GHz: {recom}")


# ──────────────────────────────────────────────
# Monitor continuo
# ──────────────────────────────────────────────
class Monitor:

    def __init__(self, intervalo: int = 10):
        self.intervalo = intervalo
        self.scanner = WiFiScanner()
        self.historial = Historial()

    def iniciar(self, ciclos: int = 0):
        """Escanea indefinidamente (ciclos=0) o N veces."""
        print(f"\n🔄 Monitor iniciado — intervalo: {self.intervalo}s  (Ctrl+C para detener)\n")
        count = 0
        try:
            while True:
                redes = self.scanner.escanear()
                os.system("cls" if os.name == "nt" else "clear")
                Visualizador.mostrar_tabla(redes)
                self.historial.guardar_escaneo(redes)
                count += 1
                if ciclos and count >= ciclos:
                    break
                time.sleep(self.intervalo)
        except KeyboardInterrupt:
            print("\n⛔ Monitor detenido.")


# ──────────────────────────────────────────────
# Visualización
# ──────────────────────────────────────────────
COLORES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "verde": "\033[92m",
    "amarillo": "\033[93m",
    "rojo": "\033[91m",
    "cyan": "\033[96m",
    "gris": "\033[90m",
}

def _color_señal(señal: int) -> str:
    if señal >= 80:
        return COLORES["verde"]
    elif señal >= 50:
        return COLORES["amarillo"]
    return COLORES["rojo"]


class Visualizador:

    @staticmethod
    def mostrar_tabla(redes: list[RedWiFi]):
        ancho = 80
        sep = "─" * ancho
        print(f"\n{COLORES['bold']}{'📡 REDES WI-FI':^{ancho}}{COLORES['reset']}")
        print(f"{COLORES['gris']}{datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^{ancho}}{COLORES['reset']}")
        print(sep)
        print(f"{'#':>3}  {'SSID':<28} {'Señal':>6}  {'Calidad':<11} {'Canal':>6}  {'Banda':<8}  {'Seguridad'}")
        print(sep)

        for i, r in enumerate(redes, 1):
            c = _color_señal(r.señal)
            barra = "▓" * (r.señal // 10) + "░" * (10 - r.señal // 10)
            lock = "🔒" if r.es_segura else "🔓"
            print(
                f"{i:>3}.  {r.ssid:<28} {c}{r.señal:>4}% {barra}{COLORES['reset']}  "
                f"{c}{r.calidad:<11}{COLORES['reset']} {r.canal:>6}  {r.banda:<8}  {lock} {r.seguridad}"
            )

        print(sep)
        print(f"  Total: {len(redes)} redes   |   "
              f"Seguras: {sum(1 for r in redes if r.es_segura)}   |   "
              f"Abiertas: {sum(1 for r in redes if not r.es_segura)}\n")

        if redes:
            mejor = redes[0]
            print(f"  🏆 Mejor señal: {COLORES['bold']}{mejor.ssid}{COLORES['reset']} "
                  f"— {mejor.señal}% ({mejor.calidad}) en canal {mejor.canal} [{mejor.banda}]")


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="📡 Escáner Wi-Fi avanzado para Windows",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--exportar-json", metavar="ARCHIVO", help="Exportar resultados a JSON")
    p.add_argument("--exportar-csv",  metavar="ARCHIVO", help="Exportar resultados a CSV")
    p.add_argument("--historial", action="store_true", help="Mostrar historial de escaneos")
    p.add_argument("--monitor", action="store_true", help="Modo monitor continuo")
    p.add_argument("--intervalo", type=int, default=10, metavar="SEG", help="Intervalo del monitor (default: 10)")
    p.add_argument("--canales", action="store_true", help="Mostrar mapa de canales y recomendación")
    p.add_argument("--filtrar-ssid", metavar="TEXTO", help="Filtrar por nombre de red (parcial)")
    p.add_argument("--solo-seguras", action="store_true", help="Mostrar solo redes con cifrado WPA/WPA2")
    p.add_argument("--sin-color", action="store_true", help="Desactivar colores ANSI")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Desactivar colores si se pide
    if args.sin_color:
        for k in COLORES:
            COLORES[k] = ""

    # Modo monitor
    if args.monitor:
        Monitor(intervalo=args.intervalo).iniciar()
        return

    # Escaneo único
    scanner = WiFiScanner()
    historial = Historial()

    logger.info("Escaneando redes Wi-Fi…")
    redes = scanner.escanear()

    # Filtros
    if args.filtrar_ssid:
        redes = [r for r in redes if args.filtrar_ssid.lower() in r.ssid.lower()]
    if args.solo_seguras:
        redes = [r for r in redes if r.es_segura]

    # Visualización principal
    Visualizador.mostrar_tabla(redes)

    # Análisis de canales
    if args.canales:
        AnalizadorCanales.mostrar_mapa(redes)

    # Exportación
    if args.exportar_json:
        Exportador.a_json(redes, args.exportar_json)
    if args.exportar_csv:
        Exportador.a_csv(redes, args.exportar_csv)

    # Historial
    historial.guardar_escaneo(redes)
    if args.historial:
        historial.listar_escaneos()


if __name__ == "__main__":
    main()
