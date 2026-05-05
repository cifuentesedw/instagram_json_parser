# Instagram Forensic Report

> Generador de reportes HTML forenses a partir de la "Descarga de información" (data takeout) de Instagram en formato JSON.

[![Version](https://img.shields.io/badge/version-2.6-informational.svg)]()
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()

Una herramienta autocontenida en un único script de Python que toma como entrada el archivo ZIP entregado por Meta cuando un usuario solicita la descarga de información de su cuenta de Instagram, y produce un reporte HTML multi-página navegable, apto para uso pericial y entrega de evidencia digital.

Desarrollado por: **Edwin Cifuentes** - **DPHIR SAS** — *Digital Forensics & Incident Response Experts*.

---

## Tabla de contenido

- [Características](#características)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Uso rápido](#uso-rápido)
- [Opciones de línea de comandos](#opciones-de-línea-de-comandos)
- [Estructura del reporte generado](#estructura-del-reporte-generado)
- [Secciones del reporte](#secciones-del-reporte)
- [Cadena de custodia y notas periciales](#cadena-de-custodia-y-notas-periciales)
- [Limitaciones conocidas](#limitaciones-conocidas)
- [Troubleshooting](#troubleshooting)
- [Contribuir](#contribuir)
- [Licencia](#licencia)

---

## Características

- **Procesa todo el takeout** — perfil, mensajes (inbox + solicitudes + canales de difusión), posts, stories, reels, fotos de perfil, contenido eliminado, conexiones, likes, comentarios, guardados, búsquedas, enlaces visitados, anuncios, dispositivos, login activity, interacciones en stories, insights, preferencias, contactos sincronizados y más.
- **Hashes triples** — calcula MD5, SHA-1 y SHA-256 del ZIP de entrada y de cada archivo multimedia individual, registrados en CSV para preservar la cadena de custodia.
- **Timeline cronológico unificado** — consolida eventos de mensajes, posts, stories, reels, logins, búsquedas y enlaces en una línea de tiempo filtrable.
- **Análisis de contactos consolidado** — estadísticas por contacto que combinan mensajes intercambiados a través de inbox, solicitudes y canales de difusión.
- **Multimedia hipervinculada** — fotos, videos y notas de voz enviadas en chats se enlazan al archivo original; reproducción inline + acceso a tamaño nativo.
- **Metadatos EXIF** — extrae cuando están disponibles datos de cámara, lente, geolocalización, fecha de captura e ID de dispositivo de las fotos y videos.
- **Normalización UTF-8** — corrige automáticamente el doble encoding ("mojibake") típico de los exports de Meta, restaurando acentos, ñ y emojis correctamente.
- **Tema claro/oscuro** — botón de toggle persistente en cada página del reporte.
- **Buscadores en vivo** — filtros JavaScript en mensajes, contactos, anunciantes y timeline.
- **Sin dependencias requeridas** — funciona con la librería estándar de Python; Pillow es opcional para EXIF avanzado.
- **Sin conexión a internet** — todo el procesamiento es local.

---

## Requisitos

- **Python 3.9 o superior** ([descargar](https://www.python.org/downloads/)).
- **Pillow** (opcional, recomendado) — habilita la extracción adicional de metadatos EXIF de imágenes JPEG.
- **Espacio en disco** equivalente a aproximadamente el doble del tamaño del ZIP de entrada (extracción + reporte).

---

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/cifuentesedw/instagram_json_parser.git
cd instagram_json_parser
```

### 2. Crear y activar un entorno virtual *(altamente recomendado)*

Aislar las dependencias en un entorno virtual evita conflictos con otros proyectos y mantiene el sistema limpio.

**En Linux / macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

**En Windows (PowerShell):**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**En Windows (cmd.exe):**

```cmd
python -m venv venv
venv\Scripts\activate.bat
```

Cuando el entorno está activo se ve un prefijo `(venv)` en el prompt.

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

Si solo necesitas la funcionalidad básica (sin EXIF avanzado), puedes omitir este paso — el script funciona sin Pillow.

### 4. Verificar instalación

```bash
python instagram_forensic_report.py --help
```

Debe imprimir el menú de ayuda con las opciones disponibles.

Para confirmar la versión instalada:

```bash
python instagram_forensic_report.py --version
# Instagram Forensic Report v2.6
```

### 5. Salir del entorno virtual *(cuando termines)*

```bash
deactivate
```

---

## Uso rápido

### Caso 1: Se cuenta con el archivo ZIP del takeout y en su interior archivos JSON

```bash
python instagram_forensic_report.py instagram-usuario-2026-03-25.zip -o reporte_forense
```

El script:

1. Extrae el ZIP a `reporte_forense/extracted/`.
2. Calcula MD5, SHA-1 y SHA-256 del ZIP completo.
3. Procesa todos los archivos JSON y multimedia.
4. Genera el reporte HTML en `reporte_forense/`.

Cuando termina, abre `reporte_forense/index.html` con cualquier navegador moderno.

### Caso 2: Ya se extrajo previamente el ZIP en una carpeta

```bash
python instagram_forensic_report.py /ruta/al/takeout_extraido -o reporte_forense --no-extract
```

### Caso 3: Iteración rápida durante pruebas (sin recalcular hashes)

```bash
python instagram_forensic_report.py takeout.zip -o reporte_forense --no-hash
```

---

## Opciones de línea de comandos

| Opción | Descripción |
|--------|-------------|
| `input` | Ruta al archivo ZIP del takeout *o* a la carpeta ya extraída |
| `-o`, `--output` | Carpeta de salida del reporte (por defecto: `./reporte_forense`) |
| `--no-extract` | El input es una carpeta ya extraída, no un ZIP |
| `--no-hash` | Omite el cálculo de MD5/SHA-1/SHA-256 (más rápido para pruebas) |
| `--no-exif` | Desactiva la extracción de EXIF con Pillow |
| `-v`, `--verbose` | Modo verboso (logging DEBUG) |
| `--version` | Muestra la versión del script (actualmente **2.6**) y termina |
| `-h`, `--help` | Muestra la ayuda y termina |

---

## Estructura del reporte generado

```
reporte_forense/
├── index.html                  # Portada con resumen ejecutivo y cadena de custodia
├── reporte_forense.log         # Log detallado de la ejecución
├── extracted/                  # Contenido del ZIP, preservado intacto
│   ├── media/
│   ├── your_instagram_activity/
│   ├── personal_information/
│   └── ...
└── report_files/               # Resto de páginas + recursos
    ├── style.css
    ├── hashes.csv              # MD5 + SHA-1 + SHA-256 de cada archivo multimedia
    ├── perfil.html
    ├── seguridad.html
    ├── dispositivos.html
    ├── contactos.html
    ├── posts.html
    ├── stories.html
    ├── reels.html
    ├── profile_photos.html
    ├── eliminados.html
    ├── conexiones.html
    ├── likes.html
    ├── comentarios.html
    ├── guardados.html
    ├── busquedas.html
    ├── enlaces_visitados.html
    ├── anuncios.html
    ├── interacciones_stories.html
    ├── visualizaciones.html
    ├── insights.html
    ├── preferencias.html
    ├── info_extra.html
    ├── timeline.html
    ├── mensajes/               # Una página por conversación del inbox
    │   ├── index.html
    │   └── <hilo>.html
    ├── solicitudes/            # Una página por message request
    │   ├── index.html
    │   └── <hilo>.html
    └── broadcast/              # Una página por canal de difusión
        ├── index.html
        └── <canal>.html
```

---

## Secciones del reporte

| Sección | Contenido |
|--------|-----------|
| **Índice** | Identificación del titular, foto de perfil, resumen ejecutivo y cadena de custodia |
| **Perfil** | Datos personales y cambios históricos del perfil |
| **Seguridad** | Inicios y cierres de sesión (fecha, IP, puerto, idioma, user-agent), creación de la cuenta |
| **Dispositivos** | Dispositivos asociados, cámaras y dispositivos de mensajes cifrados (Armadillo) |
| **Mensajes** | Conversaciones aceptadas en el inbox, una página por hilo |
| **Solicitudes** | Conversaciones provenientes de cuentas no aceptadas (forense relevante) |
| **Difusión** | Canales 1-a-muchos donde el titular es miembro o creador |
| **Contactos** | Estadísticas consolidadas por contacto (mensajes, multimedia, primer/último contacto) |
| **Posts** | Publicaciones con sus medios, leyendas y EXIF |
| **Stories** | Stories publicadas con metadatos completos |
| **Reels** | Reels con subtítulos y metadatos |
| **Foto de perfil** | Historial de fotos de perfil |
| **Eliminados** | Contenido en la papelera del takeout (todavía recuperable) |
| **Inter. Stories** | Likes, encuestas y reacciones a stories de otros |
| **Conexiones** | Seguidores, seguidos, mejores amigos, bloqueados, solicitudes |
| **Likes** | Posts y comentarios likeados |
| **Comentarios** | Comentarios escritos por el titular |
| **Guardados** | Posts marcados como guardados |
| **Búsquedas** | Búsquedas de perfil y por palabra clave |
| **Enlaces** | Enlaces visitados desde el navegador interno de Instagram |
| **Visualizaciones** | Posts y videos vistos, posts de Threads, productos vistos en shopping |
| **Anuncios** | Anuncios vistos y clicados, anunciantes que usan datos del titular, información enviada a anunciantes vía lead-gen, segmentos publicitarios |
| **Insights** | Estadísticas de cuenta como creador (audiencia, alcance, interacciones, lives) |
| **Preferencias** | Permisos de comentarios, notificaciones, mensajería entre apps, eventos, temas recomendados |
| **Info Extra** | Contactos sincronizados del teléfono, autofill, ubicación inferida, lugares de interés, info profesional |
| **Timeline** | Cronología unificada filtrable de todos los eventos |

---

## Cadena de custodia y notas periciales

1. **Hashes del ZIP de entrada.** La portada del reporte registra los tres hashes (MD5, SHA-1, SHA-256) del archivo ZIP original, su tamaño exacto y el timestamp UTC de generación del reporte.
2. **Hashes por archivo.** El archivo `report_files/hashes.csv` lista para cada uno de los archivos multimedia su ruta relativa, tamaño en bytes, MD5, SHA-1, SHA-256 y mtime UTC. Importable directamente a Excel o cualquier herramienta de análisis.
3. **Integridad de la evidencia.** El script nunca modifica los archivos extraídos: solo realiza operaciones de lectura.
4. **Reproducibilidad.** Una misma entrada produce un mismo reporte (a excepción del campo "Generado", que cambia con el timestamp de ejecución).
5. **EXIF de origen.** Para fotos y videos cargados desde la cámara del dispositivo, Instagram suele conservar los metadatos EXIF originales (modelo de cámara, ID de dispositivo iOS/Android, fecha de captura, parámetros de exposición). Útiles para correlacionar con incautaciones físicas.
6. **Normalización de texto.** El script corrige automáticamente la doble codificación UTF-8/Latin-1 propia de los exports de Meta para que acentos, eñes y emojis se rendericen correctamente. Esto se documenta al pie de cada página.
7. **Reconstrucción cronológica.** El timeline unificado consolida eventos heterogéneos (mensajes, posts, stories, reels, logins, búsquedas, enlaces) en orden temporal estricto.

---

## Limitaciones conocidas

- Si el takeout fue solicitado en formato HTML en lugar de JSON, este script no aplica. Solicita el takeout en formato JSON desde la configuración de Instagram.
- Los **mensajes cifrados de extremo a extremo** (Armadillo / "secret conversations") **no aparecen** en el JSON: Meta sólo entrega los metadatos del dispositivo asociado, no el contenido. El script lista los dispositivos en la sección Dispositivos.
- Algunas fotos no incluyen EXIF cuando Instagram las re-procesa para feed o stories.
- Las notas de voz se entregan como contenedores `.mp4` con audio AAC; el reporte usa `<audio>` HTML5 para la reproducción.

---

## Troubleshooting

**El navegador muestra los textos con caracteres extraños como `ð®` o `Ã¡`.**
El script ya aplica la corrección de mojibake. Si aparece este síntoma, asegúrate de estar abriendo la versión generada por la última versión del script y no una versión antigua.

**Los videos verticales se ven recortados al reproducirse.**
Haz doble clic sobre el video para abrirlo a tamaño nativo en una pestaña nueva. También puedes hacer clic en el enlace `▷ <nombre del archivo>` que aparece debajo de cada video.

**Pillow no se instala correctamente.**
Pillow es opcional. El script detecta su ausencia y desactiva la extracción EXIF avanzada sin afectar el resto del reporte. Si quieres usarlo, en sistemas Linux puedes necesitar instalar las cabeceras de desarrollo:

```bash
sudo apt install python3-dev libjpeg-dev zlib1g-dev    # Debian/Ubuntu
```

**El cálculo de hashes tarda mucho.**
Es normal con takeouts grandes (varios GB). Para iterar rápidamente durante pruebas usa `--no-hash`. Los hashes solo son críticos para la entrega final del reporte.

**Quiero generar el reporte sobre una carpeta extraída sin volver a descomprimir.**
Usa `--no-extract` apuntando a la carpeta donde extrajiste el ZIP previamente.

---

## Contribuir

Las contribuciones, reportes de bugs y solicitudes de mejora son bienvenidas. Por favor abre un issue o un pull request.

Para reportes de seguridad responsable, contacta directamente a [info@dphir.co](mailto:info@dphir.co).

---

## Licencia

Distribuido bajo la licencia MIT. Ver el archivo [LICENSE](LICENSE) para detalles.

---

<div align="center">

**DPHIR** — *Digital Forensics & Incident Response Experts* - [info@dphir.co](mailto:info@dphir.co)

**Edwin Cifuentes** [edwin@cifuentes.com.co](mailto:edwin@cifuentes.com.co)

Instagram Forensic Report — **v2.6**

Copyright © 2026 DPHIR — Edwin Cifuentes, Todos los derechos reservados.

</div>
