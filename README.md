# 📡 Wifi-Scanner

> Escáner avanzado de redes Wi-Fi para Windows, desarrollado en Python puro.  
> Detecta, analiza y monitorea redes cercanas con información detallada de señal, canal, banda y seguridad.


## ✨ Características

| Módulo | Descripción |
|---|---|
| 📡 **Escaneo** | Detecta todas las redes Wi-Fi cercanas vía `netsh` |
| 📊 **Análisis de canales** | Mapa visual de congestión + canal recomendado |
| 🔄 **Monitor continuo** | Refresco automático con intervalo configurable |
| 💾 **Historial** | Persiste cada escaneo en `wifi_historial.json` |
| 📤 **Exportación** | Exporta a **JSON** y **CSV** |
| 🎨 **Visualización** | Tabla con colores ANSI, barras de señal y emojis |
| 🔒 **Seguridad** | Detecta redes abiertas vs cifradas (WPA/WPA2) |
| 🌐 **Banda** | Inferencia automática 2.4 GHz / 5 GHz por canal |

---

## 🖥️ Requisitos

- **Windows** 10 / 11 (usa `netsh wlan`)
- **Python 3.9+**
- Sin dependencias externas — solo librería estándar ✅

---

## 🚀 Instalación

```bash
# Clonar el repositorio
git clone https://github.com/LuisGabrielMelo/Wifi-scanner.git
cd Wifi-scanner
```

No requiere `pip install` — corre directo.

---

## ⚙️ Uso

### Escaneo básico
```bash
python wifi_scanner.py
```

### Ver mapa de canales + recomendación
```bash
python wifi_scanner.py --canales
```

### Exportar resultados
```bash
python wifi_scanner.py --exportar-json redes.json
python wifi_scanner.py --exportar-csv  redes.csv
```

### Monitor continuo (refresco cada 5 segundos)
```bash
python wifi_scanner.py --monitor --intervalo 5
```

### Filtros
```bash
# Solo redes que contengan "Casa" en el SSID
python wifi_scanner.py --filtrar-ssid "Casa"

# Solo redes con cifrado WPA/WPA2
python wifi_scanner.py --solo-seguras
```

### Ver historial de escaneos anteriores
```bash
python wifi_scanner.py --historial
```

### Sin colores (para terminales sin soporte ANSI)
```bash
python wifi_scanner.py --sin-color
```

---

## 📋 Ejemplo de salida

```
📡                      REDES WI-FI
                   2026-02-19 11:45:03
────────────────────────────────────────────────────────────────────────────────
  #   SSID                           Señal    Calidad   Canal    Banda    Seguridad
────────────────────────────────────────────────────────────────────────────────
  1.  MiRedCasa                        85% ▓▓▓▓▓▓▓▓░░  Excelente      6  2.4 GHz  🔒 WPA2-Personal
  2.  Vecino_5G                        72% ▓▓▓▓▓▓▓░░░  Buena         36  5 GHz    🔒 WPA2-Personal
  3.  RedPublica                       41% ▓▓▓▓░░░░░░  Regular        1  2.4 GHz  🔓 Open
────────────────────────────────────────────────────────────────────────────────
  Total: 3 redes   |   Seguras: 2   |   Abiertas: 1

  🏆 Mejor señal: MiRedCasa — 85% (Excelente) en canal 6 [2.4 GHz]
```

---

## 🏗️ Estructura del proyecto

```
Wifi-scanner/
│
├── wifi_scanner.py        # Script principal
├── wifi_historial.json    # Historial de escaneos (se genera automáticamente)
├── README.md
└── .gitignore
```

---

## 🧩 Arquitectura del código

```
WiFiScanner          → Ejecuta netsh y parsea la salida
RedWiFi (dataclass)  → Modelo de datos con propiedades calculadas
Historial            → Persistencia JSON de escaneos
Exportador           → Exportación a JSON / CSV
AnalizadorCanales    → Mapa de congestión y recomendación de canal
Monitor              → Modo de escaneo continuo
Visualizador         → Tabla con colores ANSI en terminal
CLI (argparse)       → Interfaz de línea de comandos
```

---

## 📌 Opciones CLI completas

| Argumento | Descripción |
|---|---|
| `--canales` | Mapa de canales y canal recomendado |
| `--monitor` | Modo monitor continuo |
| `--intervalo SEG` | Intervalo del monitor en segundos (default: 10) |
| `--exportar-json FILE` | Exportar a JSON |
| `--exportar-csv FILE` | Exportar a CSV |
| `--filtrar-ssid TEXTO` | Filtrar redes por nombre |
| `--solo-seguras` | Mostrar solo redes WPA/WPA2 |
| `--historial` | Listar escaneos anteriores |
| `--sin-color` | Desactivar colores ANSI |

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Podés abrir un **Issue** o enviar un **Pull Request**.

1. Fork del repositorio
2. Crear una rama: `git checkout -b feature/nueva-funcionalidad`
3. Commit: `git commit -m "Agrego nueva funcionalidad"`
4. Push: `git push origin feature/nueva-funcionalidad`
5. Abrir Pull Request

---



<p align="center">Hecho con 🐍 Python por <a href="https://github.com/LuisGabrielMelo">LuisGabrielMelo</a></p>
# Wifi-scanner
📡 Advanced Wi-Fi network scanner for Windows. Built with Python — detects nearby networks, analyzes signal strength, channel congestion, security type and band (2.4/5 GHz). Features: continuous monitoring, JSON/CSV export, and persistent scan history.
