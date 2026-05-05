#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DPHIR Forensic Toolkit
============================
Generador de reporte HTML forense para "Descarga de información" (takeout)
de Instagram en formato JSON.

Autor original: Edwin Cifuentes (edwin@cifuentes.com.co)
Versión: 2.6
Licencia: MIT

Características:
  * Extrae el ZIP del takeout (o usa una carpeta ya extraída)
  * Corrige el doble-encoding UTF-8/Latin-1 ("mojibake") típico de Meta
  * Genera reporte HTML multi-página con índice navegable
  * Calcula SHA-256 de todos los medios (cadena de custodia)
  * Extrae metadatos EXIF cuando estén disponibles (vía Pillow opcional)
  * Construye timeline cronológico unificado
  * Estadísticas por conversación (cantidad de mensajes, archivos, etc.)
  * Hipervínculos a fotos/videos/audios enviados por chat
  * No requiere conexión a internet

Uso básico:
    python instagram_forensic_report.py /ruta/al/takeout.zip -o ./reporte_salida

Sin recalcular hashes (más rápido en pruebas):
    python instagram_forensic_report.py takeout.zip -o ./out --no-hash

Si ya extrajiste el ZIP a una carpeta:
    python instagram_forensic_report.py /ruta/extraida -o ./out --no-extract

Dependencias opcionales (recomendadas):
    pip install Pillow      # para extracción EXIF de imágenes JPEG

Probado con exports de Meta/Instagram en formato JSON, idiomas ES y EN version 2026
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import logging
import os
import re
import shutil
import sys
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

__version__ = "2.6"

# ---------- EXIF opcional --------------------------------------------------
try:
    from PIL import Image, ExifTags  # type: ignore
    _HAVE_PIL = True
except Exception:
    _HAVE_PIL = False

# ---------- Logging --------------------------------------------------------
log = logging.getLogger("forense")


# ===========================================================================
# UTILIDADES GENERALES
# ===========================================================================

def fix_mojibake(s: Any) -> Any:
    """
    Instagram exporta JSON con cadenas doble-codificadas: cada carácter UTF-8
    real fue interpretado como Latin-1 y vuelto a escapar como \\u00XX.
    Esta función revierte el daño cuando es posible.
    """
    if not isinstance(s, str):
        return s
    try:
        return s.encode('latin-1').decode('utf-8')
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s


def fix_obj(obj: Any) -> Any:
    """Aplica fix_mojibake recursivamente a strings dentro de dicts/listas."""
    if isinstance(obj, str):
        return fix_mojibake(obj)
    if isinstance(obj, dict):
        return {fix_mojibake(k): fix_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [fix_obj(x) for x in obj]
    return obj


def load_json(path: Path) -> Any:
    """Carga un JSON aplicando corrección de mojibake."""
    if not path.exists():
        return None
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except Exception as e:
        log.warning(f"No pude leer {path}: {e}")
        return None
    return fix_obj(data)


def safe(v: Any, default: str = "") -> str:
    """Convierte cualquier valor a string seguro para HTML."""
    if v is None:
        return default
    return str(v)


def fmt_ts(ts: Any) -> str:
    """Formatea un timestamp Unix (segundos o ms) a ISO 8601 UTC."""
    if not ts:
        return ""
    try:
        ts = int(ts)
        if ts > 10**12:  # milisegundos
            ts //= 1000
        return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return safe(ts)


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    """Calcula SHA-256 de un archivo en bloques de 1 MiB."""
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for blk in iter(lambda: fh.read(chunk), b''):
            h.update(blk)
    return h.hexdigest()


def multi_hash_file(path: Path, chunk: int = 1 << 20) -> tuple:
    """Calcula MD5, SHA-1 y SHA-256 en una sola pasada."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, 'rb') as fh:
        for blk in iter(lambda: fh.read(chunk), b''):
            md5.update(blk)
            sha1.update(blk)
            sha256.update(blk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def human_size(n: int) -> str:
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    f = float(n)
    for u in units:
        if f < 1024:
            return f"{f:.1f} {u}"
        f /= 1024
    return f"{f:.1f} PB"


def slugify(s: str, maxlen: int = 80) -> str:
    """Nombre de archivo seguro a partir de cualquier string."""
    s = re.sub(r'[^A-Za-z0-9._-]+', '_', s).strip('_')
    return (s or "sin_nombre")[:maxlen]


def rel_url(target: Path, from_page: Path) -> str:
    """URL relativa con / (Web) entre dos archivos."""
    try:
        return os.path.relpath(target, from_page.parent).replace(os.sep, '/')
    except ValueError:
        return target.as_uri()


# ===========================================================================
# ESTILO Y PLANTILLAS HTML
# ===========================================================================

CSS = """
:root, body.dark {
  --bg:#0a0d12; --panel:#13181f; --panel2:#1c232c; --border:#2a323d;
  --fg:#e8eef5; --muted:#8a96a8; --accent:#0d8bc4; --accent2:#39b6e8;
  --ok:#43d39e; --warn:#ffb84d; --danger:#ff6b6b;
  --me:#0d8bc4; --them:#1c232c;
  --shadow:0 2px 8px rgba(0,0,0,0.35);
}
body.light {
  --bg:#f3f5f8; --panel:#ffffff; --panel2:#e9eef4; --border:#d4dae2;
  --fg:#1a2230; --muted:#6b7588; --accent:#0d8bc4; --accent2:#0a6c99;
  --ok:#1a9a6c; --warn:#c97800; --danger:#c83232;
  --me:#0d8bc4; --them:#e9eef4;
  --shadow:0 2px 6px rgba(15,30,55,0.10);
}
* { box-sizing: border-box; }
body { margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
       Roboto, Helvetica, Arial, sans-serif; background:var(--bg); color:var(--fg);
       line-height:1.45; transition: background 0.2s, color 0.2s; }
header.topbar { background:linear-gradient(90deg,#0a0d12,#13262f);
  padding:12px 22px; border-bottom:2px solid var(--accent);
  display:flex; align-items:center; gap:18px; position:sticky; top:0; z-index:9;
  flex-wrap:wrap; }
body.light header.topbar { background:linear-gradient(90deg,#13181f,#1d3a4a); }
header.topbar .brand { display:flex; align-items:center; gap:12px; flex-shrink:0; }
header.topbar .brand-logo { height:38px; width:auto; }
header.topbar h1 { margin:0; font-size:15px; font-weight:600; color:#fff;
  letter-spacing:0.3px; }
header.topbar h1 .sub { display:block; font-size:11px; font-weight:400;
  color:var(--accent2); margin-top:1px; }
header.topbar nav { flex:1; min-width:0; }
header.topbar nav a { color:#cce6f5; margin-right:14px; text-decoration:none;
  font-size:13px; }
header.topbar nav a:hover { color:#fff; text-decoration:underline; }
header.topbar .theme-toggle { background:transparent; border:1px solid var(--accent);
  color:var(--accent2); padding:5px 12px; border-radius:6px; cursor:pointer;
  font-size:12px; font-weight:600; flex-shrink:0; }
header.topbar .theme-toggle:hover { background:var(--accent); color:#fff; }
.container { max-width:1180px; margin:0 auto; padding:24px; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:10px;
  padding:18px 22px; margin-bottom:18px; box-shadow:var(--shadow); }
.card h2 { margin-top:0; font-size:18px; color:var(--accent);
  border-bottom:1px solid var(--border); padding-bottom:8px; }
.card h3 { font-size:15px; color:var(--fg); margin:16px 0 8px; }
.kv { width:100%; border-collapse:collapse; }
.kv td { padding:6px 10px; border-bottom:1px solid var(--border); vertical-align:top;
  font-size:13px; }
.kv td:first-child { color:var(--muted); width:32%; font-weight:500; }
.kv td:last-child  { color:var(--fg); word-break:break-word; }
.tbl { width:100%; border-collapse:collapse; font-size:13px; }
.tbl th { background:var(--panel2); padding:8px 10px; text-align:left;
  border-bottom:2px solid var(--accent); color:var(--accent);
  position:sticky; top:62px; z-index:1; font-weight:600; }
.tbl td { padding:7px 10px; border-bottom:1px solid var(--border); vertical-align:top;
  word-break:break-word; }
.tbl tr:hover { background:rgba(13,139,196,0.07); }
.badge { display:inline-block; padding:2px 8px; border-radius:10px;
  font-size:11px; background:var(--accent); color:#fff; font-weight:600; }
.badge.warn { background:var(--warn); color:#222; }
.badge.danger { background:var(--danger); }
.badge.ok { background:var(--ok); color:#fff; }
.muted { color:var(--muted); font-size:12px; }
a { color:var(--accent2); }
body.light a { color:var(--accent); }
a.media { color:var(--accent); text-decoration:none; }
a.media:hover { text-decoration:underline; }
.thumb, .msg .thumb { max-width:300px !important; max-height:400px !important;
  width:auto !important; height:auto !important; object-fit:contain;
  border-radius:6px; border:1px solid var(--border); display:block;
  margin:4px 0; background:#000; }
.audio { width:300px; max-width:100%; display:block; }
video { width:auto; max-width:100%; max-height:560px; height:auto;
  background:#000; border-radius:6px; display:block; margin:4px 0; }
.msg video { max-width:100%; max-height:560px; }
.gallery .item video { width:100%; max-height:420px; }
/* Fullscreen: respetar el aspect-ratio nativo, sin restricciones del CSS de galería */
video:fullscreen, video:-webkit-full-screen, video:-moz-full-screen {
  width:100% !important; height:100% !important;
  max-width:100vw !important; max-height:100vh !important;
  object-fit:contain !important; background:#000 !important;
  border-radius:0 !important; margin:0 !important;
}
:fullscreen { background:#000 !important; }
::backdrop { background:#000 !important; }
/* Imágenes en galería en fullscreen via dblclick */
.gallery .item img:fullscreen, .thumb:fullscreen {
  width:100% !important; height:100% !important;
  max-width:100vw !important; max-height:100vh !important;
  object-fit:contain !important; background:#000 !important;
}
.gallery { display:grid; grid-template-columns:repeat(auto-fill,minmax(190px,1fr)); gap:12px; }
.gallery .item { background:var(--panel2); border:1px solid var(--border); border-radius:6px;
  padding:6px; font-size:11px; }
.gallery .item { display:flex; flex-direction:column; gap:4px; }
.gallery .item img, .gallery .item video, .gallery .item a > img,
.gallery .item .thumb { width:100% !important; max-width:100% !important;
  max-height:420px !important; height:auto !important; object-fit:contain !important;
  background:#000; border-radius:4px; display:block; margin:0; }
.gallery .item a.media { display:block; text-decoration:none; }
.gallery .item a.media .muted { font-size:10px; padding:2px 0; }
.msg-row { display:flex; margin:6px 0; }
.msg-row.me  { justify-content:flex-end; }
.msg-row.them{ justify-content:flex-start; }
.msg { max-width:70%; padding:8px 12px; border-radius:14px; font-size:13px; }
.msg.me  { background:var(--me); color:#fff; border-bottom-right-radius:4px; }
.msg.them{ background:var(--them); color:var(--fg); border-bottom-left-radius:4px;
  border:1px solid var(--border); }
.msg .meta { display:block; font-size:10px; color:rgba(255,255,255,0.75); margin-top:4px; }
.msg .meta a { color:rgba(255,255,255,0.9); text-decoration:underline; }
.msg.them .meta { color:var(--muted); }
.msg.them .meta a { color:var(--accent); }
.msg .reactions { font-size:11px; color:rgba(255,255,255,0.85); }
.toolbar { display:flex; gap:10px; align-items:center; margin-bottom:10px; flex-wrap:wrap; }
.toolbar input[type=search] { padding:6px 10px; border-radius:6px; border:1px solid var(--border);
  background:var(--panel2); color:var(--fg); font-size:13px; min-width:240px; }
.summary-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(170px,1fr));
  gap:12px; margin-top:10px; }
.summary-grid .stat { background:var(--panel2); border:1px solid var(--border);
  border-radius:8px; padding:12px; border-left:3px solid var(--accent); }
.summary-grid .stat b { display:block; font-size:22px; color:var(--accent); }
.summary-grid .stat span { font-size:12px; color:var(--muted); }
.profile-banner { display:flex; align-items:center; gap:24px; padding:14px 0;
  border-bottom:1px solid var(--border); margin-bottom:18px; }
.profile-banner img { width:120px; height:120px; border-radius:50%; object-fit:cover;
  border:3px solid var(--accent); box-shadow:var(--shadow); flex-shrink:0; }
.profile-banner .pi-info h3 { margin:0 0 6px; font-size:20px; color:var(--accent); }
.profile-banner .pi-info .handle { font-family: ui-monospace, monospace;
  color:var(--muted); font-size:13px; }
hr { border:0; border-top:1px solid var(--border); margin:18px 0; }
code, .mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size:12px; background:rgba(13,139,196,0.10); padding:1px 5px; border-radius:4px;
  color:var(--accent2); }
body.light code, body.light .mono { color:var(--accent); }
footer { text-align:center; color:var(--muted); padding:24px 22px; font-size:12px;
  border-top:1px solid var(--border); margin-top:30px; background:var(--panel); }
footer .brand { color:var(--accent); font-weight:700; letter-spacing:0.5px; }
footer a { color:var(--accent2); }
@media (max-width:720px){
  .summary-grid { grid-template-columns:repeat(2,1fr); }
  .msg { max-width:90%; }
  .profile-banner { flex-direction:column; text-align:center; }
  header.topbar nav a { margin-right:8px; font-size:12px; }
}
"""

LOGO_PNG_B64 = (
    "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"
)
LOGO_HTML = (
    '<img class="brand-logo" '
    'src="data:image/png;base64,' + LOGO_PNG_B64 + '" '
    'alt="DPHIR SAS — Digital Forensics &amp; Incident Response Experts">'
)
SLOGAN = "Digital Forensics &amp; Incident Response Experts"

THEME_JS = (
    "<script>(function(){"
    "var saved=(typeof localStorage!=='undefined')?localStorage.getItem('dphir-theme'):null;"
    "document.body.className=saved||'dark';"
    "window.toggleTheme=function(){"
    "var b=document.body;"
    "var n=(b.classList.contains('dark')?'light':'dark');"
    "b.className=n;"
    "try{localStorage.setItem('dphir-theme',n);}catch(e){}"
    "var btn=document.getElementById('theme-toggle');"
    "if(btn)btn.textContent=(n==='dark'?'\u2600 Claro':'\u263E Oscuro');"
    "};"
    "document.addEventListener('DOMContentLoaded',function(){"
    "var btn=document.getElementById('theme-toggle');"
    "if(btn)btn.textContent=(document.body.classList.contains('dark')?'\u2600 Claro':'\u263E Oscuro');"
    "});"
    "})();</script>"
)


NAV_LINKS = [
    ("index.html",                     "Índice"),
    ("perfil.html",                    "Perfil"),
    ("seguridad.html",                 "Seguridad"),
    ("dispositivos.html",              "Dispositivos"),
    ("mensajes/index.html",            "Mensajes"),
    ("solicitudes/index.html",         "Solicitudes"),
    ("broadcast/index.html",           "Difusión"),
    ("contactos.html",                 "Contactos"),
    ("posts.html",                     "Posts"),
    ("stories.html",                   "Stories"),
    ("interacciones_stories.html",     "Inter. Stories"),
    ("reels.html",                     "Reels"),
    ("profile_photos.html",            "Foto perfil"),
    ("eliminados.html",                "Eliminados"),
    ("conexiones.html",                "Conexiones"),
    ("likes.html",                     "Likes"),
    ("comentarios.html",               "Comentarios"),
    ("guardados.html",                 "Guardados"),
    ("busquedas.html",                 "Búsquedas"),
    ("enlaces_visitados.html",         "Enlaces"),
    ("visualizaciones.html",           "Visualizaciones"),
    ("anuncios.html",                  "Anuncios"),
    ("insights.html",                  "Insights"),
    ("preferencias.html",              "Preferencias"),
    ("info_extra.html",                "Info Extra"),
    ("timeline.html",                  "Timeline"),
]


def html_head(title: str, css_path: str) -> str:
    return f"""<!doctype html>
<html lang="es"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<link rel="stylesheet" href="{css_path}">
</head><body>
"""


def topbar(active: str, prefix_to_files: str = "",
           prefix_to_root: str = "") -> str:
    """Genera la barra superior. Cada NAV_LINK se enruta a la carpeta correcta:
       - "index.html" se resuelve contra `prefix_to_root`
       - El resto se resuelve contra `prefix_to_files`
    """
    nav_html = ""
    for href, label in NAV_LINKS:
        cls = ' style="font-weight:700;color:#fff;"' if active == href else ""
        if href == "index.html":
            full_href = f"{prefix_to_root}index.html"
        else:
            full_href = f"{prefix_to_files}{href}"
        nav_html += f'<a href="{full_href}"{cls}>{html.escape(label)}</a>'
    return f"""<header class="topbar">
  <div class="brand">{LOGO_HTML}<h1>Reporte Forense Instagram<span class="sub">DPHIR SAS &mdash; Digital Forensics &amp; Incident Response Experts</span></h1></div>
  <nav>{nav_html}</nav>
  <button id="theme-toggle" class="theme-toggle" onclick="toggleTheme()">tema</button>
</header><div class="container">
"""


def html_foot(generated: str) -> str:
    return f"""</div><footer>
<div><span class="brand">DPHIR SAS</span> &nbsp;&middot;&nbsp;
<span style="color:var(--accent2);font-style:italic;">Digital Forensics &amp; Incident Response Experts</span><br>
Reporte generado por DPHIR SAS &mdash; Todos los derechos reservados &copy; 2026<br>
<a href="mailto:info@dphir.co">info@dphir.co</a>
</div>
<div class="muted" style="margin-top:8px;">Generado el {html.escape(generated)} &middot;
Instagram Forensic Report v{__version__} &middot;
Las cadenas de texto fueron normalizadas para corregir doble-codificaci&oacute;n
UTF-8/Latin-1 propia de los exports de Meta/Instagram.</div>
</footer>{THEME_JS}</body></html>
"""


def write_page(path: Path, title: str, body_inner: str, active: str,
               prefix_to_files: str, prefix_to_root: str,
               generated: str) -> None:
    """
    prefix_to_files: prefijo URL relativo para alcanzar archivos en
                     report_files/ desde la página actual.
    prefix_to_root:  prefijo URL relativo para alcanzar la raíz del output
                     (donde vive index.html).
    """
    css_path = f"{prefix_to_files}style.css"
    page = (
        html_head(title, css_path)
        + topbar(active, prefix_to_files, prefix_to_root)
        + body_inner
        + html_foot(generated)
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(page, encoding="utf-8")


# ===========================================================================
# PARSEADORES DE LAS DISTINTAS PARTES DEL TAKEOUT
# ===========================================================================

class Takeout:
    """Acceso conveniente al árbol de un takeout extraído."""

    def __init__(self, root: Path):
        self.root = root
        self._cache: dict[Path, Any] = {}

    # acceso bajo nivel ----------------------------------------------------
    def find(self, *candidates: str) -> Path | None:
        """Devuelve el primer path existente entre los candidatos."""
        for c in candidates:
            p = self.root / c
            if p.exists():
                return p
        return None

    def load(self, *candidates: str) -> Any:
        p = self.find(*candidates)
        if p is None:
            return None
        if p in self._cache:
            return self._cache[p]
        data = load_json(p)
        self._cache[p] = data
        return data

    def glob_files(self, pattern: str) -> list[Path]:
        return sorted(self.root.glob(pattern))


def kv_from_string_map(string_map_data: dict | None) -> list[tuple[str, str]]:
    """Convierte 'string_map_data' -> lista (clave, valor formateado)."""
    if not string_map_data:
        return []
    out: list[tuple[str, str]] = []
    for k, v in string_map_data.items():
        if not isinstance(v, dict):
            out.append((str(k), safe(v)))
            continue
        ts = v.get("timestamp") or 0
        val = v.get("value", "")
        if not val and ts:
            val = fmt_ts(ts)
        elif val and ts:
            val = f"{val} <span class='muted'>({fmt_ts(ts)})</span>"
        href = v.get("href")
        if href:
            val = f'<a href="{html.escape(href)}" target="_blank" rel="noopener">{val}</a>'
        out.append((str(k), val))
    return out


# ===========================================================================
# GENERACIÓN DE PÁGINAS
# ===========================================================================

class Report:
    def __init__(self, takeout: Takeout, out_dir: Path,
                 do_hash: bool = True, do_exif: bool = True):
        self.t = takeout
        self.out = out_dir
        # Estructura del output:
        #   out_dir/index.html       <-- portada
        #   out_dir/report_files/... <-- resto + style.css + hashes.csv
        self.report_dir = out_dir / "report_files"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        (self.report_dir / "style.css").write_text(CSS, encoding="utf-8")
        self.do_hash = do_hash
        self.do_exif = do_exif
        self.generated = dt.datetime.now(dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC")
        self.timeline_events: list[tuple[int, str, str, str]] = []
        # (epoch_seconds, categoría, descripción, link relativo desde report/)
        self.media_index: dict[str, dict] = {}  # uri relativo -> {sha256, size, exif}

    # ----- helpers comunes -------------------------------------------------
    def _media_link(self, uri: str, from_page: Path,
                    label: str | None = None) -> str:
        """Genera un enlace <a> a un medio del takeout, con thumbnail si es imagen."""
        if not uri:
            return ""
        media_path = self.t.root / uri
        if not media_path.exists():
            return f'<span class="muted">[archivo no encontrado: {html.escape(uri)}]</span>'
        target_rel = rel_url(media_path, from_page)
        ext = media_path.suffix.lower()
        is_img = ext in (".jpg", ".jpeg", ".png", ".gif", ".webp")
        is_vid = ext in (".mp4", ".mov", ".webm", ".m4v")
        is_aud = ext in (".m4a", ".aac", ".mp3", ".ogg", ".wav") or (
            ext == ".mp4" and "/audio/" in uri.replace("\\", "/"))
        if label is None:
            label = media_path.name
        if is_img:
            return (f'<a class="media" href="{target_rel}" target="_blank">'
                    f'<img class="thumb" src="{target_rel}" alt="{html.escape(label)}">'
                    f'<div class="muted">{html.escape(label)}</div></a>')
        if is_vid and not is_aud:
            return (
                f'<video controls preload="metadata" playsinline '
                f'src="{target_rel}" '
                f'ondblclick="window.open(this.src, \'_blank\')"></video>'
                f'<div><a class="media" href="{target_rel}" target="_blank" '
                f'rel="noopener" title="Abrir video a tamaño nativo en nueva pestaña">'
                f'&#9655; {html.escape(label)}</a></div>')
        if is_aud:
            return (f'<audio class="audio" controls preload="none" src="{target_rel}"></audio>'
                    f'<div><a class="media" href="{target_rel}">{html.escape(label)}</a></div>')
        return f'<a class="media" href="{target_rel}">{html.escape(label)}</a>'

    def _add_event(self, ts: Any, category: str, desc: str, link: str = "") -> None:
        if not ts:
            return
        try:
            ts = int(ts)
            if ts > 10**12:
                ts //= 1000
        except Exception:
            return
        self.timeline_events.append((ts, category, desc, link))


    def _build_profile_banner(self, profile_summary: dict) -> str:
        """Construye un banner con la foto de perfil embebida en base64."""
        import base64
        d = self.t.load(
            "personal_information/personal_information/personal_information.json")
        photo_uri = ""
        if d:
            users = d.get("profile_user") or []
            if users:
                mm = (users[0].get("media_map_data") or {})
                for _label, m in mm.items():
                    if isinstance(m, dict) and m.get("uri"):
                        photo_uri = m["uri"]
                        break
        if not photo_uri:
            pp = self.t.load("your_instagram_activity/media/profile_photos.json")
            if pp:
                items = pp.get("ig_profile_picture") or []
                if items:
                    photo_uri = items[0].get("uri", "")
        username = profile_summary.get("Nombre de usuario", "") or \
                   profile_summary.get("Username", "")
        full_name = profile_summary.get("Nombre", "") or \
                    profile_summary.get("Name", "")
        bio = profile_summary.get("Presentaci\u00f3n", "") or \
              profile_summary.get("Bio", "")
        img_html = ""
        if photo_uri:
            photo_path = self.t.root / photo_uri
            if photo_path.exists():
                try:
                    raw = photo_path.read_bytes()
                    ext = photo_path.suffix.lstrip(".").lower() or "jpeg"
                    if ext == "jpg":
                        ext = "jpeg"
                    b64 = base64.b64encode(raw).decode("ascii")
                    img_html = (f'<img src="data:image/{ext};base64,{b64}" '
                                f'alt="Foto de perfil">')
                except Exception:
                    pass
        if not img_html and not (username or full_name):
            return ""
        bio_html = ""
        if bio:
            bio_safe = re.sub(r"<[^>]+>", "", str(bio))
            bio_html = (f'<div class="muted" style="margin-top:6px;'
                        f'white-space:pre-line;">'
                        f'{html.escape(bio_safe)[:280]}</div>')
        return (f'<div class="profile-banner">'
                f'{img_html}'
                f'<div class="pi-info">'
                f'<h3>{html.escape(str(full_name))}</h3>'
                f'<div class="handle">@{html.escape(str(username))}</div>'
                f'{bio_html}'
                f'</div></div>')

    # ----- 4.1 página de portada / índice --------------------------------
    def page_index(self, profile_summary: dict, takeout_meta: dict) -> None:
        # index.html va a la raíz del output, no a report_files/
        path = self.out / "index.html"

        kv_lines = "".join(
            f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
            for k, v in profile_summary.items()
            if not k.startswith("_")
        )
        meta_lines = "".join(
            f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
            for k, v in takeout_meta.items()
        )
        stats = profile_summary.get("_stats", {})
        # Banner visual con foto de perfil embebida
        profile_banner_html = self._build_profile_banner(profile_summary)
        stats_html = ""
        for label, val in stats.items():
            stats_html += (f'<div class="stat"><b>{html.escape(str(val))}</b>'
                           f'<span>{html.escape(label)}</span></div>')

        body = f"""
<div class="card">
  <h2>Resumen ejecutivo</h2>
  <p class="muted">Reporte forense de evidencia digital extraída de un export
  oficial de Instagram (Meta Platforms, Inc.). Este documento es la
  representación navegable de los archivos JSON y multimedia entregados
  por la plataforma a solicitud del titular de la cuenta.</p>
  <div class="summary-grid">{stats_html}</div>
</div>

<div class="card">
  <h2>Identificación de la cuenta</h2>
  {profile_banner_html}
  <table class="kv">{kv_lines}</table>
</div>

<div class="card">
  <h2>Cadena de custodia / metadatos del takeout</h2>
  <table class="kv">{meta_lines}</table>
  <p class="muted">Los hashes SHA-256 de cada archivo multimedia están
  disponibles en <a href="report_files/hashes.csv">hashes.csv</a>.</p>
</div>

<div class="card">
  <h2>Secciones del reporte</h2>
  <ul>
    {''.join(f'<li><a href="report_files/{href}">{html.escape(label)}</a></li>'
             for href, label in NAV_LINKS if href != "index.html")}
  </ul>
</div>
"""
        write_page(path, "Reporte Forense Instagram", body,
                   active="index.html",
                   prefix_to_files="report_files/", prefix_to_root="",
                   generated=self.generated)

    # ----- 4.2 perfil ----------------------------------------------------
    def page_profile(self) -> dict:
        """Retorna dict resumen para usar en index.html."""
        path = self.report_dir / "perfil.html"
        d = self.t.load("personal_information/personal_information/personal_information.json")
        info_html = '<p class="muted">No se encontró personal_information.json</p>'
        summary: dict = {}
        if d:
            users = d.get("profile_user") or []
            if users:
                u = users[0]
                rows = kv_from_string_map(u.get("string_map_data"))
                # Resumen para portada
                for k, v in rows:
                    summary[k] = v
                # Foto de perfil
                photo_html = ""
                for label, mm in (u.get("media_map_data") or {}).items():
                    if isinstance(mm, dict) and mm.get("uri"):
                        photo_html += (f'<h3>{html.escape(label)}</h3>'
                                       + self._media_link(mm["uri"], path))
                        self._add_event(mm.get("creation_timestamp"),
                                        "Perfil",
                                        f"{label} cargada",
                                        rel_url(self.t.root / mm["uri"], path))
                table_html = "".join(
                    f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
                    for k, v in rows
                )
                info_html = (f'<table class="kv">{table_html}</table>'
                             + photo_html)

        # Cambios de perfil
        changes = self.t.load(
            "personal_information/personal_information/profile_changes.json")
        changes_rows = ""
        if changes:
            items = changes.get("profile_profile_change") or []
            for it in items:
                m = it.get("string_map_data") or {}
                campo = (m.get("Cambios realizados") or
                         m.get("Changed") or {}).get("value", "")
                ant = (m.get("Valor anterior") or
                       m.get("Previous Value") or {}).get("value", "")
                nuevo = (m.get("Nuevo valor") or
                         m.get("New Value") or {}).get("value", "")
                ts_v = (m.get("Cambiar fecha") or
                        m.get("Change Date") or {}).get("timestamp", 0)
                changes_rows += (
                    f"<tr><td>{fmt_ts(ts_v)}</td>"
                    f"<td>{html.escape(safe(campo))}</td>"
                    f"<td><code>{html.escape(safe(ant))}</code></td>"
                    f"<td><code>{html.escape(safe(nuevo))}</code></td></tr>")
                self._add_event(ts_v, "Perfil",
                                f"Cambio: {campo}: '{ant[:60]}' → '{nuevo[:60]}'")
        changes_html = ""
        if changes_rows:
            changes_html = (
                '<div class="card"><h2>Cambios de perfil</h2>'
                '<table class="tbl"><thead><tr><th>Fecha</th><th>Campo</th>'
                '<th>Valor anterior</th><th>Valor nuevo</th></tr></thead>'
                f'<tbody>{changes_rows}</tbody></table></div>')

        body = f"""
<div class="card">
  <h2>Información de la cuenta</h2>
  {info_html}
</div>
{changes_html}
"""
        write_page(path, "Perfil — Reporte Forense", body,
                   active="perfil.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)
        return summary

    # ----- 4.3 seguridad / login -----------------------------------------
    def page_security(self) -> int:
        path = self.report_dir / "seguridad.html"
        sections = []

        def render_login_table(items: list[dict], title: str) -> str:
            rows = ""
            for it in items:
                ts_title = it.get("title", "")
                m = it.get("string_map_data") or {}
                ts = (m.get("Fecha y hora") or m.get("Time") or {}).get("timestamp", 0)
                ip = (m.get("Dirección IP") or m.get("IP Address") or {}).get("value", "")
                port = (m.get("Puerto") or m.get("Port") or {}).get("value", "")
                ua = (m.get("Agente de usuario") or m.get("User Agent") or {}).get("value", "")
                lang = (m.get("Código de idioma") or m.get("Language Code") or {}).get("value", "")
                cookie = (m.get("Nombre de cookie") or m.get("Cookie Name") or {}).get("value", "")
                fecha = fmt_ts(ts) or html.escape(safe(ts_title))
                rows += (
                    f"<tr><td>{fecha}</td>"
                    f"<td><code>{html.escape(safe(ip))}</code></td>"
                    f"<td>{html.escape(safe(port))}</td>"
                    f"<td>{html.escape(safe(lang))}</td>"
                    f"<td><span class='mono'>{html.escape(safe(cookie))}</span></td>"
                    f"<td><span class='muted'>{html.escape(safe(ua))}</span></td></tr>")
                cat = "Login" if "login" in title.lower() else "Logout"
                self._add_event(ts, cat, f"{cat} desde {ip} ({lang}) — {ua[:60]}")
            if not rows:
                return ""
            return (f'<div class="card"><h2>{html.escape(title)} '
                    f'<span class="badge">{len(items)}</span></h2>'
                    '<table class="tbl"><thead><tr>'
                    '<th>Fecha (UTC)</th><th>IP</th><th>Puerto</th>'
                    '<th>Idioma</th><th>Cookie</th><th>User-Agent</th>'
                    f'</tr></thead><tbody>{rows}</tbody></table></div>')

        login = self.t.load(
            "security_and_login_information/login_and_profile_creation/login_activity.json")
        if login:
            items = login.get("account_history_login_history") or []
            sections.append(render_login_table(items, "Inicios de sesión"))

        logout = self.t.load(
            "security_and_login_information/login_and_profile_creation/logout_activity.json")
        if logout:
            items = logout.get("account_history_logout_history") or []
            sections.append(render_login_table(items, "Cierres de sesión"))

        # Signup
        signup = self.t.load(
            "security_and_login_information/login_and_profile_creation/signup_details.json")
        if signup:
            items = signup.get("account_history_registration_info") or []
            for it in items:
                rows = kv_from_string_map(it.get("string_map_data"))
                table = "".join(f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
                                for k, v in rows)
                sections.append(
                    f'<div class="card"><h2>Registro / creación de la cuenta</h2>'
                    f'<table class="kv">{table}</table></div>')
                # Evento de creación
                m = it.get("string_map_data") or {}
                ts = (m.get("Fecha y hora") or m.get("Time") or {}).get("timestamp", 0)
                ip = (m.get("Dirección IP") or m.get("IP Address") or {}).get("value", "")
                self._add_event(ts, "Cuenta",
                                f"Creación de la cuenta desde IP {ip}")

        # Cambios de contraseña (si existen)
        pwd = self.t.load(
            "security_and_login_information/login_and_profile_creation/password_change_activity.json")
        if pwd:
            items = (pwd.get("account_history_password_history") or
                     pwd.get("password_history") or [])
            rows = ""
            for it in items:
                m = it.get("string_map_data") or {}
                rs = kv_from_string_map(m)
                rows += "<tr>" + "".join(
                    f"<td>{html.escape(k)}: {v}</td>" for k, v in rs) + "</tr>"
            if rows:
                sections.append(
                    '<div class="card"><h2>Cambios de contraseña</h2>'
                    f'<table class="tbl">{rows}</table></div>')

        body = "".join(sections) or '<div class="card"><p>Sin datos de seguridad.</p></div>'
        write_page(path, "Seguridad — Reporte Forense", body,
                   active="seguridad.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)
        return len(self.timeline_events)

    # ----- 4.4 dispositivos ----------------------------------------------
    def page_devices(self) -> None:
        path = self.report_dir / "dispositivos.html"
        cards = []
        d = self.t.load("personal_information/device_information/devices.json")
        if d:
            items = d.get("devices_devices") or []
            rows = ""
            for it in items:
                m = it.get("string_map_data") or {}
                ts = (m.get("Último inicio de sesión") or
                      m.get("Last Login") or {}).get("timestamp", 0)
                ua = (m.get("Agente de usuario") or m.get("User Agent") or {}).get("value", "")
                rows += (f"<tr><td>{fmt_ts(ts)}</td>"
                         f"<td><span class='muted'>{html.escape(safe(ua))}</span></td></tr>")
            cards.append(
                f'<div class="card"><h2>Dispositivos ({len(items)})</h2>'
                '<table class="tbl"><thead><tr><th>Último inicio (UTC)</th>'
                '<th>User-Agent</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div>')

        cam = self.t.load("personal_information/device_information/camera_information.json")
        if cam:
            items = cam.get("devices_camera") or []
            rows = ""
            for it in items:
                m = it.get("string_map_data") or {}
                rs = kv_from_string_map(m)
                rows += ("<tr>" + "".join(
                    f"<td><b>{html.escape(k)}</b><br>"
                    f"<span class='muted'>{v}</span></td>" for k, v in rs)
                         + "</tr>")
            if rows:
                cards.append(
                    f'<div class="card"><h2>Cámara ({len(items)})</h2>'
                    f'<table class="tbl"><tbody>{rows}</tbody></table></div>')

        # secret_conversations: armadillo_devices
        sc = self.t.load("your_instagram_activity/messages/secret_conversations.json")
        if sc:
            arm = (sc.get("ig_secret_conversations") or {}).get("armadillo_devices") or []
            if arm:
                rows = ""
                for d in arm:
                    rows += (
                        f"<tr><td>{html.escape(safe(d.get('device_manufacturer')))} "
                        f"{html.escape(safe(d.get('device_model')))}</td>"
                        f"<td>{html.escape(safe(d.get('device_type')))}</td>"
                        f"<td>{html.escape(safe(d.get('device_os_version')))}</td>"
                        f"<td><code>{html.escape(safe(d.get('last_connected_full_ip') or d.get('last_connected_ip')))}</code></td>"
                        f"<td>{fmt_ts(d.get('last_active_time'))}</td></tr>")
                cards.append(
                    f'<div class="card"><h2>Dispositivos con mensajes cifrados '
                    f'({len(arm)})</h2>'
                    '<table class="tbl"><thead><tr><th>Dispositivo</th><th>Tipo</th>'
                    '<th>SO</th><th>IP</th><th>Última actividad (UTC)</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table></div>')

        body = "".join(cards) or '<div class="card"><p>Sin datos de dispositivos.</p></div>'
        write_page(path, "Dispositivos — Reporte Forense", body,
                   active="dispositivos.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    # ----- 4.5 mensajes (uno por conversación) ---------------------------
    def page_messages(self) -> dict:
        """Procesa inbox/, message_requests/ y broadcast/ — 1 HTML por hilo."""
        # Procesar las 3 fuentes en sub-carpetas separadas
        inbox_stats = self._process_thread_folder(
            "inbox", "Mensajes (inbox)", "mensajes",
            "mensajes/index.html",
            "Conversaciones aceptadas en la bandeja de entrada principal.")
        req_stats = self._process_thread_folder(
            "message_requests", "Solicitudes de mensaje", "solicitudes",
            "solicitudes/index.html",
            "Conversaciones provenientes de cuentas que NO sigues; el titular "
            "no las aceptó (no se contestaron) o están en espera. "
            "Forensicamente relevantes: contactos no recurrentes / desconocidos.")
        bc_stats = self._process_thread_folder(
            "broadcast", "Canales de difusión", "broadcast",
            "broadcast/index.html",
            "Canales de difusión 1-a-muchos donde el titular es miembro o "
            "creador.")
        return {
            "threads": inbox_stats.get("threads", 0)
                       + req_stats.get("threads", 0)
                       + bc_stats.get("threads", 0),
            "contacts": inbox_stats.get("contacts", 0)
                        + req_stats.get("contacts", 0)
                        + bc_stats.get("contacts", 0),
            "inbox": inbox_stats.get("threads", 0),
            "requests": req_stats.get("threads", 0),
            "broadcast": bc_stats.get("threads", 0),
        }

    def _process_thread_folder(self, folder_name: str, label: str,
                                out_subdir: str, active_link: str,
                                description: str) -> dict:
        """Procesa una carpeta tipo inbox/message_requests/broadcast.
        Genera un index + 1 HTML por hilo. Devuelve stats."""
        msgs_root = self.report_dir / out_subdir
        msgs_root.mkdir(exist_ok=True)
        inbox = self.t.root / "your_instagram_activity" / "messages" / folder_name
        if not inbox.exists():
            write_page(msgs_root / "index.html", label,
                       f'<div class="card"><p>No se encontró la carpeta '
                       f'<code>{folder_name}</code>.</p></div>',
                       active=active_link,
prefix_to_files="../", prefix_to_root="../../",
generated=self.generated)
            return {}

        threads_meta: list[dict] = []
        per_contact_stats: dict[str, dict] = defaultdict(
            lambda: {"messages": 0, "media": 0, "first": None, "last": None,
                     "threads": set()})

        # `inbox` puede ser inbox/ message_requests/ broadcast/
        for thread_dir in sorted(inbox.iterdir()):
            if not thread_dir.is_dir():
                continue
            chunks = sorted(thread_dir.glob("message_*.json"),
                            key=lambda p: int(re.findall(r"\d+", p.stem)[0]))
            if not chunks:
                continue
            data = None
            messages: list[dict] = []
            participants: list[str] = []
            title = thread_dir.name
            for c in chunks:
                d = load_json(c)
                if not d:
                    continue
                if data is None:
                    data = d
                    title = d.get("title") or thread_dir.name
                    participants = [p.get("name", "") for p in
                                    (d.get("participants") or [])]
                messages.extend(d.get("messages") or [])
            messages.sort(key=lambda m: m.get("timestamp_ms", 0))
            slug = slugify(thread_dir.name)
            page_path = msgs_root / f"{slug}.html"

            # Render messages
            rows: list[str] = []
            owner = self._owner_name  # cuenta dueña del takeout
            n_media = 0
            ts_min, ts_max = None, None
            sender_count: Counter = Counter()
            kinds: Counter = Counter()
            for m in messages:
                sender = m.get("sender_name", "")
                sender_count[sender] += 1
                ts_ms = m.get("timestamp_ms") or 0
                ts_s = ts_ms // 1000 if ts_ms else 0
                if ts_s:
                    ts_min = ts_s if ts_min is None else min(ts_min, ts_s)
                    ts_max = ts_s if ts_max is None else max(ts_max, ts_s)
                me = (sender == owner)
                cls = "me" if me else "them"
                content = m.get("content")
                share = m.get("share")
                photos = m.get("photos") or []
                videos = m.get("videos") or []
                audios = m.get("audio_files") or []
                files = m.get("files") or []
                gifs = m.get("gifs") or []
                reactions = m.get("reactions") or []
                pieces: list[str] = []
                if content:
                    pieces.append(html.escape(content).replace("\n", "<br>"))
                for collection, kind in [(photos, "photos"), (videos, "videos"),
                                          (audios, "audio"), (files, "files"),
                                          (gifs, "gifs")]:
                    for media in collection:
                        uri = media.get("uri", "")
                        pieces.append(self._media_link(uri, page_path))
                        n_media += 1
                        kinds[kind] += 1
                if share:
                    link = share.get("link", "")
                    txt = share.get("share_text") or "Contenido compartido"
                    if link:
                        pieces.append(
                            f'<div class="muted">📎 <a href="{html.escape(link)}" '
                            f'target="_blank" rel="noopener">{html.escape(link)}</a></div>'
                            f'<div>{html.escape(txt)[:300]}</div>')
                if not pieces:
                    pieces.append('<span class="muted">[mensaje vacío / desactivado]</span>')
                react_html = ""
                if reactions:
                    rs = ", ".join(
                        f"{r.get('reaction','')} ({html.escape(r.get('actor',''))})"
                        for r in reactions)
                    react_html = f'<div class="reactions">{rs}</div>'
                meta = (f'<span class="meta"><b>{html.escape(sender)}</b> · '
                        f'{fmt_ts(ts_s)}</span>')
                rows.append(
                    f'<div class="msg-row {cls}"><div class="msg {cls}">'
                    + "".join(pieces) + react_html + meta + "</div></div>")

            # Estadísticas por contacto
            for p in participants:
                if p == owner:
                    continue
                s = per_contact_stats[p]
                s["messages"] += sender_count.get(p, 0) + sender_count.get(owner, 0)
                s["media"] += n_media
                s["threads"].add(thread_dir.name)
                s["first"] = ts_min if s["first"] is None else min(s["first"], ts_min or s["first"])
                s["last"] = ts_max if s["last"] is None else max(s["last"], ts_max or s["last"])

            # Cabecera de hilo
            participants_html = ", ".join(html.escape(p) for p in participants)
            kinds_html = ", ".join(f"{v} {k}" for k, v in kinds.items()) or "—"
            range_html = (f"{fmt_ts(ts_min)} — {fmt_ts(ts_max)}"
                          if ts_min else "(sin fechas)")
            sender_breakdown = "".join(
                f"<tr><td>{html.escape(s)}</td><td>{n}</td></tr>"
                for s, n in sender_count.most_common())
            head_card = f"""
<div class="card">
  <h2>{html.escape(title)}</h2>
  <table class="kv">
    <tr><td>Participantes</td><td>{participants_html}</td></tr>
    <tr><td>Mensajes</td><td>{len(messages)}</td></tr>
    <tr><td>Multimedia adjuntos</td><td>{n_media} ({kinds_html})</td></tr>
    <tr><td>Rango temporal</td><td>{range_html}</td></tr>
    <tr><td>Carpeta original</td><td><code>{html.escape(str(thread_dir.relative_to(self.t.root)))}</code></td></tr>
  </table>
  <h3>Mensajes por remitente</h3>
  <table class="tbl"><thead><tr><th>Remitente</th><th>Cantidad</th></tr></thead>
  <tbody>{sender_breakdown}</tbody></table>
</div>
<div class="toolbar">
  <input type="search" id="msg-filter" placeholder="Filtrar por contenido o remitente…">
  <span class="muted" id="msg-count"></span>
</div>
"""
            messages_block = "\n".join(rows) or '<p class="muted">Sin mensajes.</p>'
            script = """
<script>
const inp = document.getElementById('msg-filter');
const rows = Array.from(document.querySelectorAll('.msg-row'));
const cnt = document.getElementById('msg-count');
function refresh(){
  const q = inp.value.toLowerCase();
  let v=0;
  rows.forEach(r => {
    const show = !q || r.textContent.toLowerCase().includes(q);
    r.style.display = show ? '' : 'none';
    if(show) v++;
  });
  cnt.textContent = v + ' / ' + rows.length + ' mensajes';
}
inp.addEventListener('input', refresh); refresh();
</script>
"""
            body = head_card + '<div class="card">' + messages_block + "</div>" + script
            write_page(page_path, f"{label} — {title}", body,
                       active=active_link,
prefix_to_files="../", prefix_to_root="../../",
generated=self.generated)

            threads_meta.append({
                "slug": slug,
                "title": title,
                "n_messages": len(messages),
                "n_media": n_media,
                "first": ts_min,
                "last": ts_max,
                "participants": participants,
            })

            if ts_min:
                self._add_event(
                    ts_min * 1000, "Mensaje",
                    f"Primer mensaje de hilo «{title}»",
                    f"mensajes/{slug}.html")
            if ts_max:
                self._add_event(
                    ts_max * 1000, "Mensaje",
                    f"Último mensaje de hilo «{title}»",
                    f"mensajes/{slug}.html")

        # Index de mensajes
        threads_meta.sort(key=lambda x: x["last"] or 0, reverse=True)
        rows_html = ""
        for t in threads_meta:
            participants_short = ", ".join(p for p in t["participants"]
                                            if p != self._owner_name)[:80]
            rows_html += (
                f"<tr><td><a href='{html.escape(t['slug'])}.html'>"
                f"{html.escape(t['title'])}</a></td>"
                f"<td>{html.escape(participants_short)}</td>"
                f"<td>{t['n_messages']}</td>"
                f"<td>{t['n_media']}</td>"
                f"<td>{fmt_ts(t['first'])}</td>"
                f"<td>{fmt_ts(t['last'])}</td></tr>")
        body = f"""
<div class="card">
  <h2>{label} <span class="badge">{len(threads_meta)}</span></h2>
  <p class="muted">{description}</p>
  <div class="toolbar">
    <input type="search" id="thread-filter" placeholder="Filtrar por título / participante…">
  </div>
  <table class="tbl" id="threads">
    <thead><tr><th>Título</th><th>Participantes</th><th>Msgs</th>
    <th>Adj.</th><th>Primero</th><th>Último</th></tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
</div>
<script>
const inp=document.getElementById('thread-filter');
const tr=document.querySelectorAll('#threads tbody tr');
inp.addEventListener('input',()=>{{
  const q=inp.value.toLowerCase();
  tr.forEach(r=>r.style.display = !q||r.textContent.toLowerCase().includes(q)?'':'none');
}});
</script>
"""
        write_page(msgs_root / "index.html", f"{label} — Índice", body,
                   active=active_link,
prefix_to_files="../", prefix_to_root="../../",
generated=self.generated)

        # Acumular stats por contacto en self._all_contacts (la página
        # contactos.html se genera al final, fusionando inbox + requests + broadcast)
        if not hasattr(self, "_all_contacts"):
            self._all_contacts = {}
        for name, s in per_contact_stats.items():
            agg = self._all_contacts.setdefault(name, {
                "messages": 0, "media": 0, "first": None, "last": None,
                "threads": set(), "sources": set()
            })
            agg["messages"] += s["messages"]
            agg["media"] += s["media"]
            agg["threads"] |= s["threads"]
            agg["sources"].add(label)
            if s["first"]:
                agg["first"] = s["first"] if agg["first"] is None else min(agg["first"], s["first"])
            if s["last"]:
                agg["last"] = s["last"] if agg["last"] is None else max(agg["last"], s["last"])
        return {"threads": len(threads_meta), "contacts": len(per_contact_stats)}

    def page_contacts(self) -> None:
        """Genera contactos.html consolidando stats de inbox/requests/broadcast."""
        path = self.report_dir / "contactos.html"
        all_c = getattr(self, "_all_contacts", {})
        rows = ""
        for name, s in sorted(all_c.items(),
                               key=lambda kv: kv[1]["messages"], reverse=True):
            sources = ", ".join(sorted(s["sources"]))
            rows += (
                f"<tr><td>{html.escape(name)}</td>"
                f"<td>{s['messages']}</td>"
                f"<td>{s['media']}</td>"
                f"<td>{len(s['threads'])}</td>"
                f"<td><span class='muted'>{html.escape(sources)}</span></td>"
                f"<td>{fmt_ts(s['first'])}</td>"
                f"<td>{fmt_ts(s['last'])}</td></tr>")
        body = f"""
<div class="card">
  <h2>Estadísticas por contacto <span class="badge">{len(all_c)}</span></h2>
  <p class="muted">Consolidación de mensajes intercambiados con cada contacto
  a través de inbox, solicitudes y canales de difusión.</p>
  <div class="toolbar">
    <input type="search" id="ct-filter" placeholder="Filtrar contacto…">
  </div>
  <table class="tbl" id="cts"><thead><tr>
    <th>Contacto</th><th>Mensajes</th><th>Multimedia</th>
    <th>Hilos</th><th>Origen</th>
    <th>Primer mensaje</th><th>Último mensaje</th>
  </tr></thead><tbody>{rows}</tbody></table>
</div>
<script>
const ctIn=document.getElementById('ct-filter');
const ctTr=document.querySelectorAll('#cts tbody tr');
ctIn.addEventListener('input',()=>{{
  const q=ctIn.value.toLowerCase();
  ctTr.forEach(r=>r.style.display = !q||r.textContent.toLowerCase().includes(q)?'':'none');
}});
</script>
"""
        write_page(path, "Contactos — Reporte Forense", body,
                   active="contactos.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    # ----- 4.6 posts / stories / reels / profile_photos / deleted --------
    def _render_media_album(self, items: list[dict], from_page: Path,
                             title_field: str = "title") -> str:
        """Galería estándar para posts/stories/reels."""
        gal = []
        for it in items:
            uri = it.get("uri", "")
            ts = it.get("creation_timestamp", 0)
            title = it.get(title_field, "")
            link = self._media_link(uri, from_page) if uri else ""
            exif = ""
            md = it.get("media_metadata") or {}
            vm = md.get("video_metadata") or {}
            cm = md.get("camera_metadata") or {}
            ex = (vm.get("exif_data") or [{}])[0] if vm.get("exif_data") else {}
            if ex:
                bits = []
                for k in ("lens_model", "device_id", "date_time_original",
                          "iso", "aperture", "focal_length"):
                    v = ex.get(k)
                    if v:
                        bits.append(f"{k}: {html.escape(safe(v))}")
                if bits:
                    exif = ('<div class="muted" style="font-size:10px;">'
                            + " · ".join(bits) + "</div>")
            elif cm.get("has_camera_metadata"):
                exif = '<div class="muted">camera_metadata=true</div>'
            gal.append(
                f'<div class="item">{link}'
                f'<div class="muted">{fmt_ts(ts)}</div>'
                f'<div>{html.escape(safe(title))[:140]}</div>'
                f'{exif}</div>')
        return f'<div class="gallery">{"".join(gal)}</div>' if gal else \
               '<p class="muted">Sin elementos.</p>'

    def page_posts(self) -> None:
        path = self.report_dir / "posts.html"
        d = self.t.load("your_instagram_activity/media/posts_1.json")
        cards = []
        if isinstance(d, list):
            for i, post in enumerate(d, 1):
                medias = post.get("media") or []
                ts = post.get("creation_timestamp") or (medias[0].get("creation_timestamp")
                                                        if medias else 0)
                cap = post.get("title", "")
                gallery = self._render_media_album(medias, path)
                cards.append(
                    f'<div class="card"><h3>Post #{i} — {fmt_ts(ts)}</h3>'
                    f'<p>{html.escape(cap).replace(chr(10),"<br>")}</p>'
                    f'{gallery}</div>')
                if ts:
                    self._add_event(ts, "Post",
                                    f"Publicación: «{cap[:80]}»",
                                    f"posts.html")
        body = (f'<div class="card"><h2>Publicaciones '
                f'<span class="badge">{len(d) if isinstance(d, list) else 0}</span>'
                f'</h2></div>'
                + ("".join(cards) or
                   '<div class="card"><p>Sin publicaciones.</p></div>'))
        write_page(path, "Posts — Reporte Forense", body,
                   active="posts.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    def page_stories(self) -> None:
        path = self.report_dir / "stories.html"
        d = self.t.load("your_instagram_activity/media/stories.json")
        items = (d or {}).get("ig_stories") or []
        for it in items:
            self._add_event(it.get("creation_timestamp", 0), "Story",
                            f"Story: «{it.get('title','')[:80]}»",
                            "stories.html")
        body = (f'<div class="card"><h2>Stories <span class="badge">{len(items)}</span>'
                f'</h2>{self._render_media_album(items, path)}</div>')
        write_page(path, "Stories — Reporte Forense", body,
                   active="stories.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    def page_reels(self) -> None:
        path = self.report_dir / "reels.html"
        d = self.t.load("your_instagram_activity/media/reels.json")
        flat = []
        if d:
            for r in d.get("ig_reels_media") or []:
                flat.extend(r.get("media") or [])
        for it in flat:
            self._add_event(it.get("creation_timestamp", 0), "Reel",
                            f"Reel: «{it.get('title','')[:80]}»",
                            "reels.html")
        body = (f'<div class="card"><h2>Reels <span class="badge">{len(flat)}</span>'
                f'</h2>{self._render_media_album(flat, path)}</div>')
        write_page(path, "Reels — Reporte Forense", body,
                   active="reels.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    def page_profile_photos(self) -> None:
        path = self.report_dir / "profile_photos.html"
        d = self.t.load("your_instagram_activity/media/profile_photos.json")
        items = (d or {}).get("ig_profile_picture") or []
        for it in items:
            self._add_event(it.get("creation_timestamp", 0), "Foto perfil",
                            "Cambio de foto de perfil", "profile_photos.html")
        body = (f'<div class="card"><h2>Fotos de perfil '
                f'<span class="badge">{len(items)}</span></h2>'
                f'{self._render_media_album(items, path)}</div>')
        write_page(path, "Fotos de perfil — Reporte Forense", body,
                   active="profile_photos.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    def page_deleted(self) -> None:
        path = self.report_dir / "eliminados.html"
        d = self.t.load("your_instagram_activity/media/recently_deleted_content.json")
        flat = []
        if d:
            for r in d.get("ig_recently_deleted_media") or []:
                flat.extend(r.get("media") or [])
        for it in flat:
            self._add_event(it.get("creation_timestamp", 0), "Eliminado",
                            f"Contenido eliminado: {it.get('uri','')}",
                            "eliminados.html")
        body = (f'<div class="card"><h2>Contenido eliminado recientemente '
                f'<span class="badge danger">{len(flat)}</span></h2>'
                '<p class="muted">Estos archivos figuran en la papelera del takeout '
                '(elementos borrados pero aún recuperables al momento del export).</p>'
                f'{self._render_media_album(flat, path)}</div>')
        write_page(path, "Eliminados — Reporte Forense", body,
                   active="eliminados.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    # ----- 4.7 conexiones (followers, following, blocked, etc) ----------
    def _render_relationship_table(self, items: list[dict],
                                   key: str = "string_list_data") -> str:
        rows = ""
        for it in items:
            handle = it.get("title") or ""
            sl = it.get(key) or []
            if not isinstance(sl, list):
                sl = [sl]
            for d in sl:
                if not isinstance(d, dict):
                    continue
                value = d.get("value") or handle
                href = d.get("href", "")
                ts = d.get("timestamp", 0)
                link = (f'<a href="{html.escape(href)}" target="_blank" rel="noopener">'
                        f'{html.escape(value)}</a>' if href else html.escape(value))
                rows += f"<tr><td>{link}</td><td>{fmt_ts(ts)}</td></tr>"
        return ('<table class="tbl"><thead><tr><th>Usuario</th><th>Fecha</th>'
                f'</tr></thead><tbody>{rows}</tbody></table>')

    def page_connections(self) -> None:
        path = self.report_dir / "conexiones.html"
        cards = []

        sources = [
            ("Seguidores",
             "connections/followers_and_following/followers_1.json", None),
            ("Seguidos",
             "connections/followers_and_following/following.json",
             "relationships_following"),
            ("Mejores amigos",
             "connections/followers_and_following/close_friends.json",
             "relationships_close_friends"),
            ("Bloqueados",
             "connections/followers_and_following/blocked_profiles.json",
             "relationships_blocked_users"),
            ("Solicitudes pendientes",
             "connections/followers_and_following/pending_follow_requests.json",
             "relationships_follow_requests_sent"),
            ("Recientemente dejaste de seguir",
             "connections/followers_and_following/recently_unfollowed_profiles.json",
             "relationships_unfollowed_users"),
        ]
        for label, fname, root_key in sources:
            d = self.t.load(fname)
            if d is None:
                continue
            items = d if isinstance(d, list) else (d.get(root_key) if root_key else [])
            items = items or []
            cards.append(
                f'<div class="card"><h2>{label} '
                f'<span class="badge">{len(items)}</span></h2>'
                f'{self._render_relationship_table(items)}</div>')

        body = "".join(cards) or '<div class="card"><p>Sin datos de conexiones.</p></div>'
        write_page(path, "Conexiones — Reporte Forense", body,
                   active="conexiones.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    # ----- 4.8 likes / comentarios / guardados ---------------------------
    def page_likes(self) -> None:
        path = self.report_dir / "likes.html"
        cards = []
        # liked_posts.json: lista plana con label_values
        # liked_comments.json: dict con likes_comment_likes -> items con string_list_data
        for label, fname, root_key in [
                ("Posts likeados",
                 "your_instagram_activity/likes/liked_posts.json", None),
                ("Comentarios likeados",
                 "your_instagram_activity/likes/liked_comments.json",
                 "likes_comment_likes")]:
            d = self.t.load(fname)
            if not d:
                continue
            if isinstance(d, list):
                items = d
            elif isinstance(d, dict):
                items = d.get(root_key) if root_key else []
                if not items:
                    # Buscar primera lista del dict
                    for v in d.values():
                        if isinstance(v, list):
                            items = v
                            break
            else:
                items = []
            rows = ""
            n = 0
            for it in (items or []):
                if not isinstance(it, dict):
                    continue
                ts = it.get("timestamp", 0)
                owner = it.get("title", "")
                url = ""
                # formato 1: label_values (liked_posts.json)
                for x in it.get("label_values") or []:
                    if x.get("label") == "URL":
                        url = x.get("value") or x.get("href", "")
                    if x.get("title") in ("Propietario", "Owner"):
                        for sub in (x.get("dict") or []):
                            for sd in (sub.get("dict") or []):
                                if sd.get("label") in ("Nombre de usuario", "Username"):
                                    owner = sd.get("value", "")
                # formato 2: string_list_data (liked_comments.json)
                for sd in it.get("string_list_data") or []:
                    if not isinstance(sd, dict):
                        continue
                    if not url:
                        url = sd.get("href", "")
                    if not ts:
                        ts = sd.get("timestamp", 0)
                rows += (f"<tr><td>{fmt_ts(ts)}</td><td>{html.escape(safe(owner))}</td>"
                         f"<td><a href='{html.escape(url)}' target='_blank' "
                         f"rel='noopener'>{html.escape(url)}</a></td></tr>")
                n += 1
            cards.append(
                f'<div class="card"><h2>{label} <span class="badge">{n}</span></h2>'
                '<table class="tbl"><thead><tr><th>Fecha</th><th>Propietario</th>'
                f'<th>URL</th></tr></thead><tbody>{rows}</tbody></table></div>')
        body = "".join(cards) or '<div class="card"><p>Sin likes registrados.</p></div>'
        write_page(path, "Likes — Reporte Forense", body,
                   active="likes.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    def page_comments(self) -> None:
        path = self.report_dir / "comentarios.html"
        # los comentarios vienen en post_comments_1.json (lista) o estructuras similares
        cards = []
        for fname, label in [
                ("your_instagram_activity/comments/post_comments_1.json",
                 "Comentarios en publicaciones"),
                ("your_instagram_activity/comments/reels_comments.json",
                 "Comentarios en reels"),]:
            d = self.t.load(fname)
            if not d:
                continue
            items = d if isinstance(d, list) else (
                d.get("comments_reels_comments") or [])
            rows = ""
            for it in items:
                m = it.get("string_map_data") or {}
                comment = (m.get("Comment") or m.get("Comentario") or {}).get("value", "")
                owner = (m.get("Media Owner") or {}).get("value", "")
                ts = (m.get("Time") or {}).get("timestamp", 0)
                rows += (f"<tr><td>{fmt_ts(ts)}</td><td>{html.escape(owner)}</td>"
                         f"<td>{html.escape(comment)}</td></tr>")
            cards.append(
                f'<div class="card"><h2>{label} <span class="badge">{len(items)}</span></h2>'
                '<table class="tbl"><thead><tr><th>Fecha</th><th>Dueño</th>'
                f'<th>Comentario</th></tr></thead><tbody>{rows}</tbody></table></div>')
        body = "".join(cards) or '<div class="card"><p>Sin comentarios.</p></div>'
        write_page(path, "Comentarios — Reporte Forense", body,
                   active="comentarios.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    def page_saved(self) -> None:
        path = self.report_dir / "guardados.html"
        d = self.t.load("your_instagram_activity/saved/saved_posts.json")
        rows = ""
        items = (d or {}).get("saved_saved_media") or []
        for it in items:
            owner = it.get("title", "")
            sm = it.get("string_map_data") or {}
            saved = sm.get("Saved on") or {}
            url = saved.get("href", "")
            ts = saved.get("timestamp", 0)
            rows += (f"<tr><td>{fmt_ts(ts)}</td><td>{html.escape(owner)}</td>"
                     f"<td><a href='{html.escape(url)}' target='_blank'>{html.escape(url)}</a>"
                     f"</td></tr>")
        body = (f'<div class="card"><h2>Posts guardados '
                f'<span class="badge">{len(items)}</span></h2>'
                '<table class="tbl"><thead><tr><th>Fecha</th><th>Autor</th>'
                f'<th>URL</th></tr></thead><tbody>{rows}</tbody></table></div>')
        write_page(path, "Guardados — Reporte Forense", body,
                   active="guardados.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    # ----- 4.9 búsquedas / enlaces / anuncios ---------------------------
    def _simple_list_table(self, items: list, get_value, get_ts, label="Valor") -> str:
        rows = "".join(
            f"<tr><td>{fmt_ts(get_ts(it))}</td><td>{html.escape(safe(get_value(it)))}</td></tr>"
            for it in items)
        return ('<table class="tbl"><thead><tr><th>Fecha</th>'
                f'<th>{label}</th></tr></thead><tbody>{rows}</tbody></table>')

    def page_searches(self) -> None:
        path = self.report_dir / "busquedas.html"
        cards = []
        d = self.t.load("logged_information/recent_searches/profile_searches.json")
        if d:
            items = d.get("searches_user") or []
            rows = ""
            for it in items:
                user = it.get("title", "")
                sl = (it.get("string_list_data") or [{}])[0]
                ts = sl.get("timestamp", 0)
                href = sl.get("href", "")
                rows += (f"<tr><td>{fmt_ts(ts)}</td>"
                         f"<td><a href='{html.escape(href)}' target='_blank'>"
                         f"{html.escape(user)}</a></td></tr>")
            cards.append(
                f'<div class="card"><h2>Búsquedas de perfil '
                f'<span class="badge">{len(items)}</span></h2>'
                '<table class="tbl"><thead><tr><th>Fecha</th><th>Perfil buscado</th>'
                f'</tr></thead><tbody>{rows}</tbody></table></div>')

        d = self.t.load("logged_information/recent_searches/word_or_phrase_searches.json")
        if d:
            items = d.get("searches_keyword") or d.get("searches_user") or []
            rows = ""
            for it in items:
                kw = it.get("title", "")
                sl = (it.get("string_list_data") or [{}])[0]
                ts = sl.get("timestamp", 0)
                rows += f"<tr><td>{fmt_ts(ts)}</td><td>{html.escape(kw)}</td></tr>"
            cards.append(
                f'<div class="card"><h2>Búsquedas por palabra '
                f'<span class="badge">{len(items)}</span></h2>'
                '<table class="tbl"><thead><tr><th>Fecha</th><th>Término</th>'
                f'</tr></thead><tbody>{rows}</tbody></table></div>')

        body = "".join(cards) or '<div class="card"><p>Sin búsquedas.</p></div>'
        write_page(path, "Búsquedas — Reporte Forense", body,
                   active="busquedas.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    def page_links(self) -> None:
        path = self.report_dir / "enlaces_visitados.html"
        d = self.t.load("logged_information/link_history/link_history.json")
        rows = ""
        for it in (d or []):
            ts = it.get("timestamp", 0)
            url = title = ""
            for x in it.get("label_values") or []:
                lab = x.get("label", "").lower()
                if "url" in lab and not url:
                    url = x.get("value", "")
                if "título" in lab or "title" in lab:
                    title = x.get("value", "")
            rows += (f"<tr><td>{fmt_ts(ts)}</td>"
                     f"<td>{html.escape(title)}</td>"
                     f"<td><a href='{html.escape(url)}' target='_blank' "
                     f"rel='noopener'>{html.escape(url[:120])}…</a></td></tr>")
            self._add_event(ts, "Enlace",
                            f"Visitó: {title or url[:60]}", "enlaces_visitados.html")
        body = (f'<div class="card"><h2>Enlaces visitados '
                f'<span class="badge">{len(d or [])}</span></h2>'
                '<table class="tbl"><thead><tr><th>Fecha</th><th>Título</th>'
                f'<th>URL</th></tr></thead><tbody>{rows}</tbody></table></div>')
        write_page(path, "Enlaces visitados — Reporte Forense", body,
                   active="enlaces_visitados.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    def page_ads(self) -> None:
        path = self.report_dir / "anuncios.html"
        cards = []
        for fname, label in [
                ("ads_information/ads_and_topics/ads_clicked.json", "Anuncios clicados"),
                ("ads_information/ads_and_topics/ads_viewed.json", "Anuncios vistos"),
        ]:
            d = self.t.load(fname)
            if not d:
                continue
            items = d if isinstance(d, list) else (d.get("impressions_history_ads_clicked")
                                                    or d.get("impressions_history_ads_seen") or [])
            rows = ""
            for it in items:
                ts = it.get("timestamp", 0)
                title = ""
                url = ""
                for x in it.get("label_values") or []:
                    if x.get("label") in ("Título", "Title") and not title:
                        title = x.get("value", "")
                    if x.get("label") == "URL":
                        url = x.get("value", "") or x.get("href", "")
                rows += (f"<tr><td>{fmt_ts(ts)}</td>"
                         f"<td>{html.escape(title)}</td>"
                         f"<td><a href='{html.escape(url)}' target='_blank'>"
                         f"{html.escape(url[:100])}</a></td></tr>")
            cards.append(
                f'<div class="card"><h2>{label} <span class="badge">{len(items)}</span></h2>'
                '<table class="tbl"><thead><tr><th>Fecha</th><th>Título</th>'
                f'<th>URL</th></tr></thead><tbody>{rows}</tbody></table></div>')
        # === Cards extendidas (advertisers, info submitted, categorías) ===
        # Anunciantes que usan tu actividad
        d = self.t.load("ads_information/instagram_ads_and_businesses/advertisers_using_your_activity_or_information.json")
        if d:
            items = d.get("ig_custom_audiences_all_types") or []
            rows = ""
            for it in items:
                rows += (f"<tr><td>{html.escape(safe(it.get('advertiser_name', '')))}</td>"
                         f"<td>{'✓' if it.get('has_data_file_custom_audience') else ''}</td>"
                         f"<td>{'✓' if it.get('has_remarketing_custom_audience') else ''}</td>"
                         f"<td>{'✓' if it.get('has_in_person_store_visit') else ''}</td></tr>")
            cards.append(
                f'<div class="card"><h2>Anunciantes que usan tu actividad '
                f'<span class="badge">{len(items)}</span></h2>'
                '<p class="muted">Lista de anunciantes que han subido tu información '
                'o usan retargeting o registran tus visitas físicas.</p>'
                '<div class="toolbar"><input type="search" id="adv-filter" '
                'placeholder="Filtrar anunciante…"></div>'
                '<table class="tbl" id="adv"><thead><tr><th>Anunciante</th>'
                '<th>Lista subida</th><th>Remarketing</th><th>Visita en tienda</th>'
                f'</tr></thead><tbody>{rows}</tbody></table></div>'
                '<script>const i=document.getElementById("adv-filter");'
                'const r=document.querySelectorAll("#adv tbody tr");'
                'i.addEventListener("input",()=>{const q=i.value.toLowerCase();'
                'r.forEach(x=>x.style.display=!q||x.textContent.toLowerCase().includes(q)?"":"none");});</script>')

        # Información que has enviado a anunciantes (lead gen)
        d = self.t.load("ads_information/instagram_ads_and_businesses/information_you've_submitted_to_advertisers.json")
        if d:
            items = d.get("ig_lead_gen_info") or []
            if items:
                rows = "".join(
                    f"<tr><td>{html.escape(safe(it.get('label', '')))}</td>"
                    f"<td>{html.escape(safe(it.get('value', '')))}</td></tr>"
                    for it in items)
                cards.append(
                    '<div class="card"><h2>Información enviada a anunciantes '
                    f'<span class="badge warn">{len(items)} PII</span></h2>'
                    '<p class="muted">Datos que el titular ha enviado a anunciantes '
                    'a través de formularios de lead gen.</p>'
                    f'<table class="kv"><tbody>{rows}</tbody></table></div>')

        # Otras categorías usadas para llegar a ti
        d = self.t.load("ads_information/instagram_ads_and_businesses/other_categories_used_to_reach_you.json")
        if d:
            for x in d.get("label_values") or []:
                vec = x.get("vec") or []
                if vec:
                    label_x = x.get("label", "Categorías")
                    items_html = "".join(
                        f"<li>{html.escape(safe(v.get('value', '')))}</li>"
                        for v in vec)
                    cards.append(
                        f'<div class="card"><h2>{html.escape(label_x)} '
                        f'<span class="badge">{len(vec)}</span></h2>'
                        '<p class="muted">Atributos / segmentos publicitarios '
                        'asociados al perfil.</p>'
                        f'<ul>{items_html}</ul></div>')

        # Ads about Meta
        d = self.t.load("ads_information/instagram_ads_and_businesses/ads_about_meta.json")
        if d:
            rows = ""
            for x in d.get("label_values") or []:
                lab = x.get("label", "")
                if "timestamp_value" in x:
                    val = fmt_ts(x.get("timestamp_value", 0))
                else:
                    val = x.get("value", "")
                rows += (f"<tr><td>{html.escape(safe(lab))}</td>"
                         f"<td>{html.escape(safe(val))}</td></tr>")
            if rows:
                cards.append(
                    '<div class="card"><h2>Configuración "Anuncios sobre Meta"</h2>'
                    f'<table class="kv"><tbody>{rows}</tbody></table></div>')

        body = "".join(cards) or '<div class="card"><p>Sin anuncios.</p></div>'
        write_page(path, "Anuncios — Reporte Forense", body,
                   active="anuncios.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)


    # ----- Stories interactions ----------------------------------------------
    def page_story_interactions(self) -> None:
        path = self.report_dir / "interacciones_stories.html"
        cards = []
        for fname, label, root_key in [
            ("your_instagram_activity/story_interactions/story_likes.json",
             "Likes en stories de otros", None),
            ("your_instagram_activity/story_interactions/polls.json",
             "Encuestas respondidas", "story_activities_polls"),
            ("your_instagram_activity/story_interactions/emoji_story_reactions.json",
             "Reacciones rápidas con emoji",
             "story_activities_emoji_quick_reactions"),
            ("your_instagram_activity/story_interactions/story_reaction_sticker_reactions.json",
             "Reacciones con sticker",
             "story_activities_reaction_sticker_reactions"),
        ]:
            d = self.t.load(fname)
            if not d:
                continue
            if isinstance(d, list):
                items = d
            else:
                items = d.get(root_key) if root_key else []
                if not items:
                    for v in d.values():
                        if isinstance(v, list):
                            items = v
                            break
            rows = ""
            for it in (items or []):
                if not isinstance(it, dict):
                    continue
                user = it.get("title", "")
                ts = it.get("timestamp", 0)
                value = ""
                url = ""
                # Format 1: label_values (story_likes)
                for x in it.get("label_values") or []:
                    if x.get("label") == "URL":
                        url = x.get("value", "")
                    if x.get("title") == "Propietario":
                        for sub in (x.get("dict") or []):
                            for sd in (sub.get("dict") or []):
                                if sd.get("label") in ("Nombre de usuario", "Username"):
                                    user = sd.get("value", "") or user
                # Format 2: string_list_data (polls, reactions)
                for sd in it.get("string_list_data") or []:
                    if isinstance(sd, dict):
                        if not ts:
                            ts = sd.get("timestamp", 0)
                        if not value:
                            value = sd.get("value", "")
                        if not url:
                            url = sd.get("href", "")
                rows += (f"<tr><td>{fmt_ts(ts)}</td>"
                         f"<td>{html.escape(safe(user))}</td>"
                         f"<td>{html.escape(safe(value))}</td>"
                         f"<td>" +
                         (f"<a href='{html.escape(url)}' target='_blank'>"
                          f"{html.escape(url[:80])}</a>" if url else "") +
                         "</td></tr>")
            cards.append(
                f'<div class="card"><h2>{label} '
                f'<span class="badge">{len(items or [])}</span></h2>'
                '<table class="tbl"><thead><tr><th>Fecha</th><th>Usuario</th>'
                '<th>Valor</th><th>URL</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div>')
        body = "".join(cards) or '<div class="card"><p>Sin interacciones.</p></div>'
        write_page(path, "Interacciones en Stories — Reporte Forense", body,
                   active="interacciones_stories.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    # ----- Información extra (contactos sincronizados, ubicaciones, etc) -----
    def page_info_extra(self) -> None:
        path = self.report_dir / "info_extra.html"
        cards = []

        # Synced contacts (libreta de teléfono sincronizada)
        d = self.t.load("connections/contacts/synced_contacts.json")
        if d:
            items = d.get("contacts_contact_info") or []
            rows = ""
            for it in items:
                m = it.get("string_map_data") or {}
                fn = (m.get("First Name") or {}).get("value", "")
                ln = (m.get("Last Name") or {}).get("value", "")
                ci = (m.get("Contact Information") or {}).get("value", "")
                rows += (f"<tr><td>{html.escape(safe(fn))} "
                         f"{html.escape(safe(ln))}</td>"
                         f"<td><code>{html.escape(safe(ci))}</code></td></tr>")
            cards.append(
                f'<div class="card"><h2>Contactos sincronizados '
                f'<span class="badge warn">{len(items)}</span></h2>'
                '<p class="muted">Libreta del dispositivo sincronizada con la cuenta '
                '(Instagram lee contactos del teléfono si el usuario lo permite). '
                'Material PII sensible.</p>'
                '<div class="toolbar"><input type="search" id="sc-filter" '
                'placeholder="Filtrar contacto…"></div>'
                '<table class="tbl" id="sc"><thead><tr><th>Nombre</th>'
                f'<th>Contacto</th></tr></thead><tbody>{rows}</tbody></table></div>'
                '<script>const i=document.getElementById("sc-filter");'
                'const r=document.querySelectorAll("#sc tbody tr");'
                'i.addEventListener("input",()=>{const q=i.value.toLowerCase();'
                'r.forEach(x=>x.style.display=!q||x.textContent.toLowerCase().includes(q)?"":"none");});</script>')

        # Autofill information
        d = self.t.load("personal_information/autofill_information/autofill_information.json")
        if d:
            data = d.get("ig_autofill_data", {}) or {}
            rows = "".join(
                f"<tr><td>{html.escape(k)}</td><td>{html.escape(safe(v))}</td></tr>"
                for k, v in data.items() if v
            )
            if rows:
                cards.append(
                    '<div class="card"><h2>Información de autocompletado '
                    '<span class="badge warn">PII</span></h2>'
                    '<p class="muted">Datos guardados por la app para autocompletar '
                    'formularios (teléfono, dirección, email).</p>'
                    f'<table class="kv"><tbody>{rows}</tbody></table></div>')

        # Ubicación inferida
        d = self.t.load("personal_information/information_about_you/profile_based_in.json")
        if d:
            items = d.get("inferred_data_primary_location") or []
            rows = ""
            for it in items:
                rs = kv_from_string_map(it.get("string_map_data"))
                rows += "".join(
                    f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
                    for k, v in rs)
            if rows:
                cards.append(
                    '<div class="card"><h2>Ubicación principal inferida</h2>'
                    '<p class="muted">Ciudad inferida por Instagram usando IP, '
                    'geolocalización del dispositivo y patrones de uso.</p>'
                    f'<table class="kv"><tbody>{rows}</tbody></table></div>')

        # Lugares de interés
        d = self.t.load("personal_information/information_about_you/locations_of_interest.json")
        if d:
            lvs = d.get("label_values") or []
            for x in lvs:
                vec = x.get("vec") or []
                if vec:
                    label_x = x.get("label", "Lugares")
                    items_html = "".join(
                        f"<li>{html.escape(safe(v.get('value', '')))}</li>"
                        for v in vec)
                    cards.append(
                        f'<div class="card"><h2>{html.escape(label_x)} '
                        f'<span class="badge">{len(vec)}</span></h2>'
                        '<p class="muted">Lugares geográficos asociados al perfil '
                        'según los anunciantes / actividad.</p>'
                        f'<ul>{items_html}</ul></div>')

        # Información profesional / negocio
        d = self.t.load("personal_information/personal_information/professional_information.json")
        if d:
            items = d.get("profile_business") or []
            for it in items:
                rs = kv_from_string_map(it.get("string_map_data"))
                rows = "".join(
                    f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
                    for k, v in rs if v)
                if rows:
                    cards.append(
                        f'<div class="card"><h2>{html.escape(safe(it.get("title", "Información de empresa")))}</h2>'
                        f'<table class="kv"><tbody>{rows}</tbody></table></div>')

        # Note interactions (Instagram Notes)
        d = self.t.load("personal_information/personal_information/note_interactions.json")
        if d:
            items = d.get("profile_note_interactions") or []
            if items:
                rows = ""
                for it in items:
                    rs = kv_from_string_map(it.get("string_map_data"))
                    rows += "".join(
                        f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
                        for k, v in rs)
                cards.append(
                    '<div class="card"><h2>Interacciones con Notas</h2>'
                    f'<table class="kv"><tbody>{rows}</tbody></table></div>')

        # Friend map
        d = self.t.load("personal_information/personal_information/instagram_friend_map.json")
        if d:
            items = d.get("profile_friend_map") or []
            if items:
                rows = ""
                for it in items:
                    rs = kv_from_string_map(it.get("string_map_data"))
                    rows += "".join(
                        f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
                        for k, v in rs)
                cards.append(
                    '<div class="card"><h2>Mapa de amigos</h2>'
                    f'<table class="kv"><tbody>{rows}</tbody></table></div>')

        # Avatar items (Meta Avatar)
        d = self.t.load("your_instagram_activity/avatars_store/avatar_items.json")
        if d:
            items = d.get("ig_avatar_marketplace_avatar_items") or []
            if items:
                rows = "".join(
                    f"<tr><td>{html.escape(safe(it.get('item','')))}</td>"
                    f"<td>{html.escape(safe(it.get('type','')))}</td>"
                    f"<td>{fmt_ts(it.get('acquisition_time'))}</td></tr>"
                    for it in items)
                cards.append(
                    f'<div class="card"><h2>Ítems de Avatar Meta '
                    f'<span class="badge">{len(items)}</span></h2>'
                    '<table class="tbl"><thead><tr><th>Ítem</th><th>Tipo</th>'
                    f'<th>Adquisición</th></tr></thead><tbody>{rows}</tbody></table></div>')

        body = "".join(cards) or '<div class="card"><p>Sin información extra.</p></div>'
        write_page(path, "Información Extra — Reporte Forense", body,
                   active="info_extra.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    # ----- Historial de visualizaciones -------------------------------------
    def page_visualizaciones(self) -> None:
        path = self.report_dir / "visualizaciones.html"
        cards = []
        for fname, label, kind in [
            ("ads_information/ads_and_topics/posts_viewed.json",
             "Posts vistos", "Posts"),
            ("ads_information/ads_and_topics/videos_watched.json",
             "Videos vistos", "Videos"),
        ]:
            d = self.t.load(fname)
            if not d:
                continue
            items = d if isinstance(d, list) else []
            rows = ""
            for it in items:
                ts = it.get("timestamp", 0)
                url = ""; author = ""
                for x in it.get("label_values") or []:
                    if x.get("label") == "URL":
                        url = x.get("value", "") or x.get("href", "")
                    if x.get("label") in ("Autor", "Author"):
                        author = x.get("value", "")
                rows += (f"<tr><td>{fmt_ts(ts)}</td>"
                         f"<td>{html.escape(author)}</td>"
                         f"<td><a href='{html.escape(url)}' target='_blank'>"
                         f"{html.escape(url[:80])}</a></td></tr>")
            cards.append(
                f'<div class="card"><h2>{label} <span class="badge">{len(items)}</span></h2>'
                '<table class="tbl"><thead><tr><th>Fecha</th><th>Autor</th>'
                f'<th>URL</th></tr></thead><tbody>{rows}</tbody></table></div>')

        # Threads viewed (Meta Threads app)
        d = self.t.load("your_instagram_activity/threads/threads_viewed.json")
        if d:
            items = d.get("text_post_app_text_post_app_posts_seen") or []
            rows = ""
            for it in items:
                m = it.get("string_map_data") or {}
                author = (m.get("Author") or {}).get("value", "")
                ts = (m.get("Time") or {}).get("timestamp", 0)
                url = (m.get("URL") or {}).get("href", "")
                rows += (f"<tr><td>{fmt_ts(ts)}</td>"
                         f"<td>{html.escape(author)}</td>"
                         f"<td><a href='{html.escape(url)}' target='_blank'>"
                         f"{html.escape(url[:80])}</a></td></tr>")
            if rows:
                cards.append(
                    f'<div class="card"><h2>Posts de Threads vistos '
                    f'<span class="badge">{len(items)}</span></h2>'
                    '<table class="tbl"><thead><tr><th>Fecha</th><th>Autor</th>'
                    f'<th>URL</th></tr></thead><tbody>{rows}</tbody></table></div>')

        # Productos vistos (Shopping)
        d = self.t.load("your_instagram_activity/shopping/recently_viewed_items.json")
        if d:
            items = d.get("checkout_saved_recently_viewed_products") or []
            rows = ""
            for it in items:
                m = it.get("string_map_data") or {}
                pn = (m.get("Product Name") or {}).get("value", "")
                mn = (m.get("Merchant Name") or {}).get("value", "")
                rows += (f"<tr><td>{html.escape(pn)}</td>"
                         f"<td>{html.escape(mn)}</td></tr>")
            if rows:
                cards.append(
                    f'<div class="card"><h2>Productos vistos recientemente '
                    f'<span class="badge">{len(items)}</span></h2>'
                    '<table class="tbl"><thead><tr><th>Producto</th>'
                    f'<th>Vendedor</th></tr></thead><tbody>{rows}</tbody></table></div>')

        body = "".join(cards) or '<div class="card"><p>Sin historial.</p></div>'
        write_page(path, "Historial de Visualizaciones — Reporte Forense", body,
                   active="visualizaciones.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    # ----- Insights de cuenta (estadísticas pasadas) -------------------------
    def page_insights(self) -> None:
        path = self.report_dir / "insights.html"
        cards = []
        for fname, label, root_key in [
            ("logged_information/past_instagram_insights/audience_insights.json",
             "Insights de audiencia", "organic_insights_audience"),
            ("logged_information/past_instagram_insights/profiles_reached.json",
             "Cuentas alcanzadas", "organic_insights_reach"),
            ("logged_information/past_instagram_insights/content_interactions.json",
             "Interacciones con contenido", "organic_insights_interactions"),
            ("logged_information/past_instagram_insights/live_videos.json",
             "Videos en vivo", "organic_insights_live"),
        ]:
            d = self.t.load(fname)
            if not d:
                continue
            items = d.get(root_key) or []
            rows = ""
            for it in items:
                rs = kv_from_string_map(it.get("string_map_data"))
                if not rs:
                    continue
                inner = "".join(
                    f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
                    for k, v in rs)
                rows += (f'<tr><td colspan="2"><table class="kv">'
                         f'<tbody>{inner}</tbody></table></td></tr>')
            if rows:
                cards.append(
                    f'<div class="card"><h2>{label} <span class="badge">{len(items)}</span></h2>'
                    '<table class="tbl"><tbody>'
                    f'{rows}</tbody></table></div>')
        body = "".join(cards) or '<div class="card"><p>Sin insights.</p></div>'
        write_page(path, "Insights — Reporte Forense", body,
                   active="insights.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    # ----- Preferencias / configuraciones -----------------------------------
    def page_preferencias(self) -> None:
        path = self.report_dir / "preferencias.html"
        cards = []

        d = self.t.load("preferences/settings/comments_allowed_from.json")
        if d:
            items = d.get("settings_allow_comments_from") or []
            rows = ""
            for it in items:
                rs = kv_from_string_map(it.get("string_map_data"))
                rows += "".join(
                    f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
                    for k, v in rs)
            if rows:
                cards.append(
                    '<div class="card"><h2>Permisos de comentarios</h2>'
                    f'<table class="kv"><tbody>{rows}</tbody></table></div>')

        d = self.t.load("preferences/settings/use_cross-app_messaging.json")
        if d:
            items = d.get("settings_upgraded_to_cross_app_messaging") or []
            rows = ""
            for it in items:
                rs = kv_from_string_map(it.get("string_map_data"))
                rows += "".join(
                    f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
                    for k, v in rs)
            if rows:
                cards.append(
                    '<div class="card"><h2>Mensajería entre aplicaciones</h2>'
                    '<p class="muted">Indica si la cuenta migró al sistema de mensajería '
                    'unificado de Meta (Messenger ↔ Instagram).</p>'
                    f'<table class="kv"><tbody>{rows}</tbody></table></div>')

        d = self.t.load("preferences/settings/notification_preferences.json")
        if d:
            items = d.get("settings_notification_preferences") or []
            rows = ""
            for it in items:
                m = it.get("string_map_data") or {}
                ch = (m.get("Channel") or {}).get("value", "")
                ty = (m.get("Type") or {}).get("value", "")
                vl = (m.get("Value") or {}).get("value", "")
                rows += (f"<tr><td>{html.escape(ch)}</td>"
                         f"<td>{html.escape(ty)}</td>"
                         f"<td>{html.escape(vl)}</td></tr>")
            if rows:
                cards.append(
                    f'<div class="card"><h2>Preferencias de notificaciones '
                    f'<span class="badge">{len(items)}</span></h2>'
                    '<table class="tbl"><thead><tr><th>Canal</th><th>Tipo</th>'
                    f'<th>Valor</th></tr></thead><tbody>{rows}</tbody></table></div>')

        d = self.t.load("preferences/your_topics/recommended_topics.json")
        if d:
            items = d.get("topics_your_topics") or []
            rows = ""
            for it in items:
                m = it.get("string_map_data") or {}
                nm = (m.get("Nombre") or m.get("Name") or {}).get("value", "")
                if nm:
                    rows += f"<tr><td>{html.escape(nm)}</td></tr>"
            if rows:
                cards.append(
                    f'<div class="card"><h2>Temas recomendados '
                    f'<span class="badge">{len(items)}</span></h2>'
                    '<p class="muted">Categorías inferidas para personalizar contenido.</p>'
                    '<table class="tbl"><thead><tr><th>Tema</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table></div>')

        d = self.t.load("your_instagram_activity/events/event_reminders.json")
        if d:
            items = d.get("events_event_reminders") or []
            rows = ""
            for it in items:
                user = it.get("title", "")
                sl = (it.get("string_list_data") or [{}])[0]
                ts = sl.get("timestamp", 0)
                rows += (f"<tr><td>{html.escape(user)}</td>"
                         f"<td>{fmt_ts(ts)}</td></tr>")
            if rows:
                cards.append(
                    f'<div class="card"><h2>Recordatorios de eventos '
                    f'<span class="badge">{len(items)}</span></h2>'
                    '<table class="tbl"><thead><tr><th>Cuenta</th>'
                    f'<th>Fecha</th></tr></thead><tbody>{rows}</tbody></table></div>')

        # Subscripciones
        d = self.t.load("your_instagram_activity/subscriptions/your_muted_story_teaser_creators.json")
        if d:
            items = d.get("user_muted_story_teaser_creators") or \
                    next((v for v in (d.values() if isinstance(d, dict) else []) \
                          if isinstance(v, list)), [])
            if items:
                rows = "".join(
                    f"<tr><td>{html.escape(safe(i.get('title', '')))}</td></tr>"
                    for i in items if isinstance(i, dict))
                if rows:
                    cards.append(
                        f'<div class="card"><h2>Creadores muteados '
                        f'<span class="badge">{len(items)}</span></h2>'
                        '<table class="tbl"><thead><tr><th>Cuenta</th></tr></thead>'
                        f'<tbody>{rows}</tbody></table></div>')

        body = "".join(cards) or '<div class="card"><p>Sin preferencias.</p></div>'
        write_page(path, "Preferencias — Reporte Forense", body,
                   active="preferencias.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    # ----- 4.10 timeline unificado ---------------------------------------
    def page_timeline(self) -> None:
        path = self.report_dir / "timeline.html"
        events = sorted(self.timeline_events, key=lambda e: e[0])
        rows = ""
        for ts, cat, desc, link in events:
            link_html = (f'<a href="{html.escape(link)}">ver</a>' if link else "")
            rows += (f"<tr><td>{fmt_ts(ts)}</td>"
                     f"<td><span class='badge'>{html.escape(cat)}</span></td>"
                     f"<td>{html.escape(desc)}</td>"
                     f"<td>{link_html}</td></tr>")
        body = f"""
<div class="card">
  <h2>Timeline cronológico unificado <span class="badge">{len(events)}</span></h2>
  <p class="muted">Eventos consolidados de mensajes, posts, stories, reels,
  logins, búsquedas y enlaces, ordenados temporalmente. Útil para
  reconstruir cronologías en sede pericial.</p>
  <div class="toolbar">
    <input type="search" id="tl-filter" placeholder="Filtrar…">
  </div>
  <table class="tbl" id="tl">
    <thead><tr><th>Fecha (UTC)</th><th>Categoría</th><th>Descripción</th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<script>
const tlIn=document.getElementById('tl-filter');
const tlRows=document.querySelectorAll('#tl tbody tr');
tlIn.addEventListener('input',()=>{{
  const q=tlIn.value.toLowerCase();
  tlRows.forEach(r=>r.style.display = !q||r.textContent.toLowerCase().includes(q)?'':'none');
}});
</script>
"""
        write_page(path, "Timeline — Reporte Forense", body,
                   active="timeline.html",
prefix_to_files="", prefix_to_root="../",
generated=self.generated)

    # ----- 4.11 hashes SHA-256 de medios --------------------------------
    def hash_media(self) -> dict:
        """Recorre archivos multimedia y calcula MD5, SHA-1 y SHA-256."""
        out_csv = self.report_dir / "hashes.csv"
        roots = ["media", "your_instagram_activity/messages/inbox"]
        stats = {"files": 0, "bytes": 0}
        with open(out_csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["ruta_relativa", "tamaño_bytes",
                        "md5", "sha1", "sha256", "modificado_utc"])
            for r in roots:
                base = self.t.root / r
                if not base.exists():
                    continue
                for f in base.rglob("*"):
                    if not f.is_file():
                        continue
                    if f.suffix.lower() == ".json":
                        continue
                    try:
                        sz = f.stat().st_size
                        if self.do_hash:
                            md5, sha1, sha256 = multi_hash_file(f)
                        else:
                            md5 = sha1 = sha256 = ""
                    except Exception as e:
                        log.warning(f"hash {f}: {e}")
                        continue
                    rel = str(f.relative_to(self.t.root))
                    mtime = dt.datetime.fromtimestamp(
                        f.stat().st_mtime, tz=dt.timezone.utc).isoformat()
                    w.writerow([rel, sz, md5, sha1, sha256, mtime])
                    stats["files"] += 1
                    stats["bytes"] += sz
        log.info(f"Hashes (MD5+SHA1+SHA256): {stats['files']} archivos, "
                 f"{human_size(stats['bytes'])}, CSV → {out_csv}")
        return stats

    # ----- entry point ---------------------------------------------------
    def build(self, takeout_meta: dict) -> dict:
        self._owner_name = self._detect_owner()
        log.info(f"Cuenta detectada: {self._owner_name}")

        log.info("→ perfil")
        profile = self.page_profile()
        log.info("→ seguridad / login")
        self.page_security()
        log.info("→ dispositivos")
        self.page_devices()
        log.info("→ mensajes (inbox + solicitudes + difusión, esto puede tomar tiempo)")
        msg_stats = self.page_messages()
        log.info(f"  Inbox: {msg_stats.get('inbox',0)} hilos, "
                 f"Solicitudes: {msg_stats.get('requests',0)} hilos, "
                 f"Difusión: {msg_stats.get('broadcast',0)} hilos, "
                 f"{msg_stats.get('contacts',0)} contactos únicos")
        log.info("→ contactos consolidados")
        self.page_contacts()
        log.info("→ posts")
        self.page_posts()
        log.info("→ stories")
        self.page_stories()
        log.info("→ reels")
        self.page_reels()
        log.info("→ fotos de perfil")
        self.page_profile_photos()
        log.info("→ interacciones en stories")
        self.page_story_interactions()
        log.info("→ contenido eliminado")
        self.page_deleted()
        log.info("→ conexiones")
        self.page_connections()
        log.info("→ likes")
        self.page_likes()
        log.info("→ comentarios")
        self.page_comments()
        log.info("→ guardados")
        self.page_saved()
        log.info("→ búsquedas")
        self.page_searches()
        log.info("→ enlaces visitados")
        self.page_links()
        log.info("→ historial de visualizaciones")
        self.page_visualizaciones()
        log.info("→ anuncios (extendido)")
        self.page_ads()
        log.info("→ insights de cuenta")
        self.page_insights()
        log.info("→ preferencias / configuraciones")
        self.page_preferencias()
        log.info("→ información extra (PII, ubicaciones, contactos sincronizados)")
        self.page_info_extra()

        log.info("→ hashes SHA-256 de medios")
        hash_stats = self.hash_media()

        log.info("→ timeline cronológico")
        self.page_timeline()

        # Stats para portada
        profile["_stats"] = {
            "Conversaciones (inbox)": msg_stats.get("inbox", 0),
            "Solicitudes de mensaje": msg_stats.get("requests", 0),
            "Canales de difusión": msg_stats.get("broadcast", 0),
            "Contactos únicos": msg_stats.get("contacts", 0),
            "Eventos timeline": len(self.timeline_events),
            "Archivos multimedia": hash_stats["files"],
            "Volumen multimedia": human_size(hash_stats["bytes"]),
        }
        log.info("→ portada / índice")
        self.page_index(profile, takeout_meta)
        return {"messages": msg_stats, "hashes": hash_stats}

    def _detect_owner(self) -> str:
        d = self.t.load(
            "personal_information/personal_information/personal_information.json")
        if d:
            users = d.get("profile_user") or []
            if users:
                m = users[0].get("string_map_data") or {}
                # nombre completo
                name = (m.get("Nombre") or m.get("Name") or {}).get("value")
                if name:
                    return name
        # fallback: el sender más frecuente en los mensajes
        return ""


# ===========================================================================
#  EXTRACCIÓN DEL ZIP
# ===========================================================================

def extract_zip(zip_path: Path, dest_dir: Path) -> dict:
    dest_dir.mkdir(parents=True, exist_ok=True)
    log.info(f"Extrayendo {zip_path.name} en {dest_dir}…")
    t0 = time.time()
    with zipfile.ZipFile(zip_path) as zf:
        n = len(zf.namelist())
        zf.extractall(dest_dir)
    elapsed = time.time() - t0
    log.info(f"Extraídos {n} elementos en {elapsed:.1f}s")
    log.info("Calculando hashes MD5 / SHA-1 / SHA-256 del ZIP…")
    md5, sha1, sha256 = multi_hash_file(zip_path)
    return {
        "Archivo ZIP": f"<code>{html.escape(zip_path.name)}</code>",
        "Tamaño ZIP": human_size(zip_path.stat().st_size),
        "MD5 del ZIP": f"<code>{md5}</code>",
        "SHA-1 del ZIP": f"<code>{sha1}</code>",
        "SHA-256 del ZIP": f"<code>{sha256}</code>",
        "Archivos extraídos": str(n),
        "Tiempo de extracción": f"{elapsed:.1f} s",
        "Carpeta destino": f"<code>{html.escape(str(dest_dir))}</code>",
        "Generado": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


# ===========================================================================
# LINEA DE COMANDOS - CLI
# ===========================================================================

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Genera reporte HTML forense desde un takeout de Instagram",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("input", type=Path,
                   help="ZIP del takeout o carpeta ya extraída")
    p.add_argument("-o", "--output", type=Path, default=Path("./reporte_forense"),
                   help="Carpeta de salida del reporte")
    p.add_argument("--no-extract", action="store_true",
                   help="No extraer (input es una carpeta ya extraída)")
    p.add_argument("--no-hash", action="store_true",
                   help="No calcular SHA-256 (más rápido para pruebas)")
    p.add_argument("--no-exif", action="store_true",
                   help="No extraer EXIF de imágenes con Pillow")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version",
                   version=f"Instagram Forensic Report v{__version__}")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S")

    args.output.mkdir(parents=True, exist_ok=True)
    log_file = args.output / "reporte_forense.log"
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s"))
    logging.getLogger().addHandler(fh)

    log.info("=" * 60)
    log.info(f"INSTAGRAM FORENSIC REPORT v{__version__}")
    log.info(f"Input : {args.input}")
    log.info(f"Output: {args.output}")
    log.info("=" * 60)

    extracted_dir = args.output / "extracted"
    if args.no_extract:
        extracted_dir = args.input
        if not extracted_dir.exists() or not extracted_dir.is_dir():
            log.error("--no-extract requiere que input sea una carpeta válida")
            return 2
        meta = {
            "Carpeta de entrada": f"<code>{html.escape(str(extracted_dir))}</code>",
            "Modo": "Sin extracción (carpeta pre-existente)",
            "Generado": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
    else:
        if not args.input.is_file():
            log.error(f"Input ZIP no existe: {args.input}")
            return 2
        meta = extract_zip(args.input, extracted_dir)

    takeout = Takeout(extracted_dir)
    rep = Report(takeout, args.output,
                 do_hash=not args.no_hash,
                 do_exif=not args.no_exif)
    stats = rep.build(meta)

    log.info("=" * 60)
    log.info("REPORTE GENERADO")
    log.info(f"Abrir: {(args.output / 'index.html').resolve()}")
    log.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
