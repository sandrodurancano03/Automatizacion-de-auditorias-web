#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebAudit Pro v2.0
Herramienta de auditoría de seguridad web automatizada para Kali Linux.

Fases:
  1. Reconocimiento   — nmap, whatweb, wafw00f, whois, shodan (opcional)
  2. Descubrimiento   — wfuzz (fuzzing de directorios/archivos)
  3. Evasión          — detección de mecanismos de defensa y técnicas de bypass
  4. Escaneo          — nikto, sslscan, nuclei, cabeceras HTTP
  5. Recopilación     — extracción de metadatos, emails, JS endpoints
  6. Explotación      — sqlmap (inyección SQL), XSS básico, LFI/RFI checks
  7. Reporte          — HTML en español con hallazgos clasificados

Correcciones v2.0:
  - Bug wfuzz: el formato JSON es un array completo, no líneas JSONL.
  - Se añade fallback a parseo JSONL por si el archivo está corrupto.
  - Nuevas fases: Evasión y Recopilación de información.
  - Módulo de cabeceras HTTP de seguridad.
  - Módulo de verificación de XSS básico y LFI.
  - Módulo de extracción de metadatos (emails, endpoints JS, comentarios).
"""

import subprocess
import sys
import os
import json
import re
import signal
import time
import shutil
import socket
import hashlib
import base64
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs, quote
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Tuple
import xml.etree.ElementTree as ET

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.columns import Columns
from rich import box

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    Template = None
    JINJA2_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r'''
 ██╗    ██╗███████╗██████╗  █████╗ ██╗   ██╗██████╗ ██╗████████╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
 ██║ █╗ ██║█████╗  ██████╔╝███████║██║   ██║██║  ██║██║   ██║   
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██║██║   ██║██║  ██║██║   ██║   
 ╚███╔███╔╝███████╗██████╔╝██║  ██║╚██████╔╝██████╔╝██║   ██║   
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   
                    ╔═╗╦═╗╔═╗                                   
                    ╠═╝╠╦╝║ ║                                   
                    ╩  ╩╚═╚═╝  v2.0                             
'''

DISCLAIMER = (
    "AVISO LEGAL: Esta herramienta está diseñada exclusivamente para realizar "
    "auditorías de seguridad en sistemas para los cuales usted tiene autorización "
    "expresa y por escrito. El uso no autorizado de esta herramienta contra sistemas "
    "de terceros es ilegal y puede constituir un delito penal.\n\n"
    "El autor no se hace responsable del uso indebido de esta herramienta. "
    "Al utilizar WebAudit Pro, usted acepta toda la responsabilidad legal "
    "derivada de su uso.\n\n"
    "Solo proceda si tiene permiso explícito del propietario del sistema objetivo."
)

TOOLS = {
    "nmap":       "Escáner de puertos y servicios",
    "whatweb":    "Detección de tecnologías web",
    "wafw00f":    "Detección de WAF (Web Application Firewall)",
    "whois":      "Consulta de información de dominio",
    "wfuzz":      "Fuzzing de directorios y archivos",
    "nikto":      "Escáner de vulnerabilidades web",
    "sslscan":    "Análisis de configuración SSL/TLS",
    "nuclei":     "Escáner de vulnerabilidades basado en plantillas",
    "sqlmap":     "Detección y explotación de inyección SQL",
    "dig":        "Consultas DNS avanzadas",
    "curl":       "Peticiones HTTP / análisis de cabeceras",
    "exiftool":   "Extracción de metadatos de archivos",
    "burpsuite":  "Proxy de interceptación (lanzamiento manual)",
}

SEVERITY_MAP = {
    "critico": "bold red",
    "alto":    "red",
    "medio":   "yellow",
    "bajo":    "blue",
    "info":    "dim cyan",
}

WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/wfuzz/general/common.txt",
    "/usr/share/wordlists/dirb/small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

# Patrones de clasificación de rutas descubiertas
ADMIN_PATTERNS    = re.compile(r"(admin|administrator|wp-admin|phpmyadmin|cpanel|manager|login|dashboard|panel)", re.IGNORECASE)
BACKUP_PATTERNS   = re.compile(r"\.(bak|old|backup|sql|zip|tar\.gz|tar|gz|rar|7z|dump)$", re.IGNORECASE)
CONFIG_PATTERNS   = re.compile(r"(\.env|\.htaccess|web\.config|wp-config|config\.(php|yml|yaml|json|xml|ini))", re.IGNORECASE)
SENSITIVE_PATTERNS = re.compile(r"(\.git|\.svn|\.DS_Store|\.hg|\.bzr|\.idea|\.vscode)", re.IGNORECASE)

# Cabeceras de seguridad HTTP que deben estar presentes
SECURITY_HEADERS = {
    "Strict-Transport-Security":    "Protege contra ataques de downgrade HTTPS (HSTS).",
    "Content-Security-Policy":      "Mitiga ataques XSS y de inyección de datos.",
    "X-Frame-Options":              "Previene ataques de clickjacking.",
    "X-Content-Type-Options":       "Previene MIME sniffing.",
    "Referrer-Policy":              "Controla la información del referente.",
    "Permissions-Policy":           "Controla el acceso a APIs del navegador.",
    "X-XSS-Protection":             "Activación del filtro XSS del navegador (deprecada, informativa).",
}

# Cargas útiles de evasión / bypass básico
WAF_BYPASS_HEADERS = [
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
]

# Payloads XSS básicos para detección (sin ejecución real)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]

# Payloads LFI básicos para detección
LFI_PAYLOADS = [
    "../etc/passwd",
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "/etc/passwd",
    "....//....//etc/passwd",
]


# ─────────────────────────────────────────────────────────────────────────────
# Dataclass para hallazgos
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """Representa un hallazgo individual de seguridad."""
    tool: str
    severity: str       # 'critico', 'alto', 'medio', 'bajo', 'info'
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    phase: str = ""     # Fase de la auditoría donde se detectó


# ─────────────────────────────────────────────────────────────────────────────
# Clase principal
# ─────────────────────────────────────────────────────────────────────────────

class WebAuditPro:
    """Orquestador principal de la auditoría de seguridad web."""

    def __init__(self):
        self.console = Console()
        self.target_url: str = ""
        self.target_host: str = ""
        self.target_ip: str = ""
        self.target_port: int = 80
        self.is_https: bool = False
        self.workdir: Path = Path("/tmp")
        self.findings: List[Finding] = []
        self.open_ports: List[dict] = []
        self.technologies: List[str] = []
        self.waf_detected: Optional[str] = None
        self.directories_found: List[dict] = []
        self.ssl_info: Optional[dict] = None
        self.whois_info: str = ""
        self.dns_info: dict = {}
        self.http_headers: dict = {}
        self.security_headers_missing: List[str] = []
        self.security_headers_present: List[str] = []
        self.nuclei_results: List[dict] = []
        self.sqlmap_results: List[str] = []
        self.metadata_results: dict = {
            "emails": [],
            "js_endpoints": [],
            "comments": [],
            "robots_entries": [],
            "sitemap_urls": [],
        }
        self.evasion_results: dict = {
            "waf_bypass_tested": False,
            "bypass_headers_effective": [],
            "encoding_tested": False,
            "lfi_vulnerable": [],
            "xss_reflected": [],
        }
        self.start_time: Optional[datetime] = None
        self.tools_available: Dict[str, bool] = {}

    # ─────────────────────────────────────────────────────────────────
    # Interfaz de usuario
    # ─────────────────────────────────────────────────────────────────

    def show_banner(self):
        """Muestra el banner de la herramienta."""
        self.console.print(
            Panel(
                Text(BANNER, style="cyan"),
                border_style="cyan",
                subtitle="[dim]Auditoría Web Automatizada para Kali Linux — v2.0[/dim]",
            )
        )

    def show_disclaimer(self):
        """Muestra el aviso legal y solicita aceptación."""
        self.console.print()
        self.console.print(
            Panel(
                DISCLAIMER,
                title="[bold red]⚠  AVISO LEGAL  ⚠[/]",
                border_style="red",
                padding=(1, 2),
            )
        )
        self.console.print()
        accepted = Confirm.ask("[bold yellow]¿Aceptas los términos de uso?[/]")
        if not accepted:
            self.console.print("[bold red]Auditoría cancelada. No se aceptaron los términos.[/]")
            sys.exit(0)
        self.console.print("[green]Términos aceptados. Continuando...[/]\n")

    def get_target(self):
        """Solicita y configura el objetivo de la auditoría."""
        self.console.print(
            Panel(
                "[bold]Introduce la URL o dirección IP del objetivo.\n"
                "Ejemplos: https://ejemplo.com, 192.168.1.100, ejemplo.com:8080[/]",
                title="[bold cyan]🎯 Objetivo[/]",
                border_style="cyan",
            )
        )
        raw = Prompt.ask("[bold cyan]Objetivo[/]").strip()

        if not raw:
            self.console.print("[bold red]Error: No se proporcionó ningún objetivo.[/]")
            sys.exit(1)

        # Si no tiene esquema, asumir http
        if not re.match(r"^https?://", raw, re.IGNORECASE):
            raw = f"http://{raw}"

        parsed = urlparse(raw)
        self.target_host = parsed.hostname or ""
        self.target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.is_https = parsed.scheme == "https"
        self.target_url = f"{parsed.scheme}://{self.target_host}"
        if self.target_port not in (80, 443):
            self.target_url += f":{self.target_port}"
        if parsed.path and parsed.path != "/":
            self.target_url += parsed.path

        # Resolver IP
        try:
            self.target_ip = socket.gethostbyname(self.target_host)
        except socket.gaierror:
            self.console.print(
                f"[bold red]Error: No se pudo resolver el host '{self.target_host}'.[/]"
            )
            sys.exit(1)

        # Mostrar resumen
        info_table = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
        info_table.add_column("Campo", style="bold cyan")
        info_table.add_column("Valor", style="white")
        info_table.add_row("URL",     self.target_url)
        info_table.add_row("Host",    self.target_host)
        info_table.add_row("IP",      self.target_ip)
        info_table.add_row("Puerto",  str(self.target_port))
        info_table.add_row("HTTPS",   "Sí" if self.is_https else "No")
        self.console.print(
            Panel(info_table, title="[bold green]Información del Objetivo[/]", border_style="green")
        )
        self.console.print()

    def check_root(self):
        """Comprueba si se ejecuta como root."""
        if os.geteuid() != 0:
            self.console.print(
                Panel(
                    "[yellow]No estás ejecutando como root. Algunas herramientas "
                    "(nmap SYN scan, etc.) pueden requerir privilegios elevados "
                    "y podrían no funcionar correctamente.[/]",
                    title="[bold yellow]⚠  Advertencia[/]",
                    border_style="yellow",
                )
            )
            if not Confirm.ask("[yellow]¿Deseas continuar sin privilegios de root?[/]"):
                self.console.print("[bold red]Auditoría cancelada.[/]")
                sys.exit(0)
            self.console.print()

    def check_tools(self):
        """Verifica la disponibilidad de cada herramienta del sistema."""
        self.console.print(Rule("[bold cyan]Verificación de Herramientas[/]", style="cyan"))
        self.console.print()

        table = Table(
            title="Estado de Herramientas",
            box=box.ROUNDED,
            show_lines=True,
            title_style="bold cyan",
        )
        table.add_column("Herramienta", style="bold white", min_width=12)
        table.add_column("Descripción", style="dim")
        table.add_column("Estado", justify="center", min_width=8)

        available_count = 0
        for tool_name, description in TOOLS.items():
            found = shutil.which(tool_name) is not None
            self.tools_available[tool_name] = found
            status = "[green]✅ OK[/]" if found else "[red]❌ No encontrado[/]"
            if found:
                available_count += 1
            table.add_row(tool_name, description, status)

        # Verificar requests
        requests_status = "[green]✅ OK[/]" if REQUESTS_AVAILABLE else "[yellow]⚠ No instalado[/]"
        table.add_row("requests (Python)", "Análisis HTTP interno", requests_status)
        if REQUESTS_AVAILABLE:
            available_count += 1

        self.console.print(table)
        self.console.print(
            f"\n[bold]Herramientas disponibles: "
            f"[green]{available_count}[/]/{len(TOOLS) + 1}[/]\n"
        )

        if available_count == 0:
            self.console.print(
                "[bold red]Error: No se encontró ninguna herramienta. "
                "Instala las herramientas necesarias antes de continuar.[/]"
            )
            sys.exit(1)

    def setup_workdir(self):
        """Crea el directorio de trabajo con subdirectorios por fase."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.workdir = Path(f"/tmp/webaudit_{ts}")
        subdirs = ["recon", "discovery", "evasion", "vulnscan", "collection", "exploit"]
        for d in subdirs:
            (self.workdir / d).mkdir(parents=True, exist_ok=True)
        self.console.print(f"[dim]Directorio de trabajo: {self.workdir}[/]\n")

    # ─────────────────────────────────────────────────────────────────
    # Ejecución de comandos
    # ─────────────────────────────────────────────────────────────────

    def run_cmd(self, cmd: str, timeout: int = 300, cwd: Optional[str] = None) -> Tuple[str, str, int]:
        """
        Ejecuta un comando del sistema de forma segura.

        Returns:
            (stdout, stderr, returncode) — en caso de error devuelve ('', error_msg, -1).
        """
        work = cwd or str(self.workdir)
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=work,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            self.console.print(
                f"  [yellow]⚠  Tiempo de espera agotado ({timeout}s) para: "
                f"{cmd[:80]}...[/]"
            )
            return "", f"Timeout después de {timeout}s", -1
        except Exception as exc:
            self.console.print(f"  [red]✗ Error ejecutando comando: {exc}[/]")
            return "", str(exc), -1

    def _http_get(self, url: str, headers: dict = None, timeout: int = 15) -> Optional[requests.Response]:
        """Realiza una petición GET usando requests si está disponible."""
        if not REQUESTS_AVAILABLE:
            return None
        try:
            default_headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
            }
            if headers:
                default_headers.update(headers)
            resp = requests.get(
                url,
                headers=default_headers,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            return resp
        except Exception:
            return None

    # ─────────────────────────────────────────────────────────────────
    # FASE 1: Reconocimiento
    # ─────────────────────────────────────────────────────────────────

    def phase_recon(self):
        """Ejecuta la fase de reconocimiento."""
        self.console.print()
        self.console.print(Rule("[bold cyan]FASE 1: RECONOCIMIENTO[/]", style="cyan"))
        self.console.print()

        tasks = [
            ("nmap",    "Escaneo de puertos y servicios",    self.run_nmap),
            ("whatweb", "Detección de tecnologías",          self.run_whatweb),
            ("wafw00f", "Detección de WAF",                  self.run_wafw00f),
            ("whois",   "Consulta WHOIS",                    self.run_whois),
            ("dig",     "Consultas DNS",                     self.run_dns),
        ]

        for tool_name, desc, func in tasks:
            if not self.tools_available.get(tool_name, False):
                # dig y whois son comunes; mostrar advertencia
                self.console.print(f"  [dim]⊘ {tool_name} no disponible — omitiendo {desc}[/]")
                continue
            with self.console.status(f"[cyan]Ejecutando {desc}...[/]", spinner="dots"):
                try:
                    summary = func()
                except Exception as exc:
                    summary = f"Error: {exc}"
                    self.console.print(f"  [red]✗ {tool_name} falló: {exc}[/]")
                    continue
            self.console.print(f"  [green]✓[/] {tool_name} completado — {summary}")

        # Análisis de cabeceras HTTP (no requiere herramienta externa si requests disponible)
        with self.console.status("[cyan]Analizando cabeceras HTTP de seguridad...[/]", spinner="dots"):
            try:
                summary = self.analyze_http_headers()
            except Exception as exc:
                summary = f"Error: {exc}"
        self.console.print(f"  [green]✓[/] Cabeceras HTTP analizadas — {summary}")

    def run_nmap(self) -> str:
        """Ejecuta nmap y analiza los resultados XML."""
        xml_path = self.workdir / "recon" / "nmap.xml"
        cmd = (
            f"nmap -sV -sC --top-ports 1000 -T4 "
            f"-oX {xml_path} {self.target_host}"
        )
        stdout, stderr, rc = self.run_cmd(cmd, timeout=300)

        try:
            if xml_path.exists():
                tree = ET.parse(str(xml_path))
                root = tree.getroot()

                for host_el in root.findall(".//host"):
                    for port_el in host_el.findall(".//port"):
                        state_el = port_el.find("state")
                        if state_el is None or state_el.get("state") != "open":
                            continue
                        service_el = port_el.find("service")
                        port_info = {
                            "port":     port_el.get("portid", "?"),
                            "protocol": port_el.get("protocol", "tcp"),
                            "service":  (
                                service_el.get("name", "desconocido")
                                if service_el is not None else "desconocido"
                            ),
                            "version":  (
                                f"{service_el.get('product', '')} "
                                f"{service_el.get('version', '')}".strip()
                                if service_el is not None else ""
                            ),
                        }
                        self.open_ports.append(port_info)

                        # Scripts NSE que indiquen vulnerabilidades
                        for script_el in port_el.findall(".//script"):
                            script_id  = script_el.get("id", "")
                            script_out = script_el.get("output", "")
                            if any(kw in script_id.lower() for kw in ("vuln", "exploit", "brute", "enum")):
                                self.findings.append(
                                    Finding(
                                        tool="nmap",
                                        severity="medio",
                                        title=f"Script NSE: {script_id}",
                                        description=script_out[:500],
                                        evidence=f"Puerto {port_info['port']}/{port_info['protocol']}",
                                        recommendation="Revisar el servicio expuesto y aplicar parches si es necesario.",
                                        phase="reconocimiento",
                                    )
                                )
        except ET.ParseError as exc:
            self.console.print(f"  [yellow]⚠  Error parseando XML de nmap: {exc}[/]")
        except Exception as exc:
            self.console.print(f"  [yellow]⚠  Error procesando nmap: {exc}[/]")

        if self.open_ports:
            pt = Table(
                title="Puertos Abiertos",
                box=box.SIMPLE_HEAVY,
                title_style="bold green",
            )
            pt.add_column("Puerto", style="bold")
            pt.add_column("Protocolo")
            pt.add_column("Servicio", style="cyan")
            pt.add_column("Versión", style="dim")
            for p in self.open_ports:
                pt.add_row(p["port"], p["protocol"], p["service"], p["version"])
            self.console.print(pt)

        return f"{len(self.open_ports)} puertos abiertos encontrados"

    def run_whatweb(self) -> str:
        """Ejecuta whatweb para detección de tecnologías."""
        json_path = self.workdir / "recon" / "whatweb.json"
        cmd = f"whatweb -a 3 --log-json={json_path} {self.target_url}"
        stdout, stderr, rc = self.run_cmd(cmd, timeout=120)

        try:
            if json_path.exists():
                raw = json_path.read_text(encoding="utf-8", errors="replace")
                data = []
                try:
                    data = json.loads(raw)
                    if not isinstance(data, list):
                        data = [data]
                except json.JSONDecodeError:
                    for line in raw.strip().splitlines():
                        line = line.strip()
                        if line:
                            try:
                                obj = json.loads(line)
                                if isinstance(obj, list):
                                    data.extend(obj)
                                else:
                                    data.append(obj)
                            except json.JSONDecodeError:
                                continue

                for entry in data:
                    plugins = entry.get("plugins", {})
                    for plugin_name, plugin_data in plugins.items():
                        if plugin_name in ("Title", "IP", "Country", "HTTPServer"):
                            continue
                        version_str = ""
                        if isinstance(plugin_data, dict):
                            versions = plugin_data.get("version", [])
                            if versions:
                                version_str = f" ({', '.join(str(v) for v in versions)})"
                        tech = f"{plugin_name}{version_str}"
                        if tech not in self.technologies:
                            self.technologies.append(tech)
        except Exception as exc:
            self.console.print(f"  [yellow]⚠  Error procesando whatweb: {exc}[/]")

        if self.technologies:
            self.console.print(
                f"  [dim]Tecnologías: {', '.join(self.technologies[:15])}"
                f"{'...' if len(self.technologies) > 15 else ''}[/]"
            )

        return f"{len(self.technologies)} tecnologías detectadas"

    def run_wafw00f(self) -> str:
        """Ejecuta wafw00f para detectar WAF."""
        json_path = self.workdir / "recon" / "wafw00f.json"
        cmd = f"wafw00f {self.target_url} -o {json_path} -f json"
        stdout, stderr, rc = self.run_cmd(cmd, timeout=60)

        try:
            combined = stdout + stderr
            if json_path.exists():
                raw = json_path.read_text(encoding="utf-8", errors="replace")
                try:
                    data = json.loads(raw)
                    if isinstance(data, list):
                        for entry in data:
                            firewall = entry.get("firewall", "")
                            if firewall and firewall.lower() not in ("none", "generic", ""):
                                self.waf_detected = firewall
                    elif isinstance(data, dict):
                        firewall = data.get("firewall", "")
                        if firewall and firewall.lower() not in ("none", "generic", ""):
                            self.waf_detected = firewall
                except json.JSONDecodeError:
                    pass

            if self.waf_detected is None and combined:
                waf_match = re.search(
                    r"is behind (?:a |an )?(.+?)(?:\s+WAF|\s*$)",
                    combined,
                    re.IGNORECASE,
                )
                if waf_match:
                    self.waf_detected = waf_match.group(1).strip()
        except Exception as exc:
            self.console.print(f"  [yellow]⚠  Error procesando wafw00f: {exc}[/]")

        if self.waf_detected:
            self.findings.append(
                Finding(
                    tool="wafw00f",
                    severity="info",
                    title="WAF Detectado",
                    description=f"Se detectó un Web Application Firewall: {self.waf_detected}",
                    evidence=f"Identificado por wafw00f en {self.target_url}",
                    recommendation=(
                        "Tener en cuenta que el WAF puede filtrar tráfico malicioso. "
                        "Los resultados de las pruebas pueden verse afectados."
                    ),
                    phase="reconocimiento",
                )
            )
            return f"WAF detectado: {self.waf_detected}"
        return "No se detectó WAF"

    def run_whois(self) -> str:
        """Ejecuta consulta WHOIS (solo para dominios, no IPs)."""
        is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", self.target_host)
        if is_ip:
            return "Omitido (objetivo es una IP)"

        cmd = f"whois {self.target_host}"
        stdout, stderr, rc = self.run_cmd(cmd, timeout=30)
        self.whois_info = stdout if stdout else ""

        if self.whois_info:
            registrar = ""
            creation  = ""
            expiry    = ""
            for line in self.whois_info.splitlines():
                line_lower = line.lower().strip()
                if "registrar:" in line_lower and not registrar:
                    registrar = line.split(":", 1)[-1].strip()
                if "creation date:" in line_lower and not creation:
                    creation = line.split(":", 1)[-1].strip()
                if "expiry date:" in line_lower or "expiration date:" in line_lower:
                    if not expiry:
                        expiry = line.split(":", 1)[-1].strip()

            detail = ""
            if registrar:
                detail += f"Registrar: {registrar}  "
            if creation:
                detail += f"Creación: {creation}  "
            if expiry:
                detail += f"Expiración: {expiry}"
            if detail:
                self.console.print(f"  [dim]{detail}[/]")
            return "Información WHOIS obtenida"
        return "Sin resultados WHOIS"

    def run_dns(self) -> str:
        """Realiza consultas DNS usando dig."""
        is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", self.target_host)
        if is_ip:
            return "Omitido (objetivo es una IP)"

        dns_file = self.workdir / "recon" / "dns.txt"
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        results = {}

        with open(dns_file, "w") as f:
            for rtype in record_types:
                cmd = f"dig +noall +answer {self.target_host} {rtype}"
                stdout, _, _ = self.run_cmd(cmd, timeout=15)
                if stdout.strip():
                    results[rtype] = stdout.strip()
                    f.write(f"=== {rtype} ===\n{stdout}\n\n")

        self.dns_info = results

        # Detectar transferencia de zona (axfr) — solo si hay servidores NS
        if "NS" in results:
            ns_lines = results["NS"].splitlines()
            for ns_line in ns_lines[:3]:
                parts = ns_line.split()
                if parts:
                    ns_server = parts[-1].rstrip(".")
                    cmd = f"dig @{ns_server} {self.target_host} axfr"
                    stdout, _, rc = self.run_cmd(cmd, timeout=20)
                    if stdout and "Transfer failed" not in stdout and rc == 0:
                        if len(stdout.strip().splitlines()) > 5:
                            self.findings.append(
                                Finding(
                                    tool="dig",
                                    severity="critico",
                                    title="Transferencia de zona DNS posible (AXFR)",
                                    description=(
                                        f"El servidor de nombres {ns_server} permite "
                                        f"transferencias de zona, exponiendo todos los "
                                        f"registros DNS del dominio."
                                    ),
                                    evidence=f"dig @{ns_server} {self.target_host} axfr",
                                    recommendation=(
                                        "Configurar el servidor DNS para rechazar "
                                        "transferencias de zona a clientes no autorizados."
                                    ),
                                    phase="reconocimiento",
                                )
                            )
                        break

        # Mostrar registros encontrados
        if results:
            dns_table = Table(
                title="Registros DNS",
                box=box.SIMPLE_HEAVY,
                title_style="bold green",
            )
            dns_table.add_column("Tipo", style="bold cyan", width=6)
            dns_table.add_column("Valor", style="dim")
            for rtype, val in results.items():
                first_line = val.splitlines()[0] if val else ""
                dns_table.add_row(rtype, first_line[:120])
            self.console.print(dns_table)

        return f"{len(results)} tipos de registros DNS obtenidos"

    def analyze_http_headers(self) -> str:
        """Analiza las cabeceras HTTP de seguridad del servidor."""
        if not REQUESTS_AVAILABLE:
            # Usar curl como fallback
            if not self.tools_available.get("curl", False):
                return "No disponible (se requiere requests o curl)"
            cmd = f"curl -sI --max-time 15 -A 'Mozilla/5.0' {self.target_url}"
            stdout, _, _ = self.run_cmd(cmd, timeout=20)
            headers_raw = stdout
            # Parsear cabeceras desde curl
            for line in headers_raw.splitlines():
                if ":" in line:
                    key, _, val = line.partition(":")
                    self.http_headers[key.strip()] = val.strip()
        else:
            resp = self._http_get(self.target_url)
            if resp is None:
                return "No se pudo conectar al servidor"
            self.http_headers = dict(resp.headers)

        if not self.http_headers:
            return "No se pudieron obtener cabeceras HTTP"

        # Verificar cabeceras de seguridad
        for header, description in SECURITY_HEADERS.items():
            found = any(h.lower() == header.lower() for h in self.http_headers)
            if found:
                self.security_headers_present.append(header)
            else:
                self.security_headers_missing.append(header)
                # No reportar X-XSS-Protection como faltante (deprecada)
                if header != "X-XSS-Protection":
                    severity = "medio" if header in (
                        "Content-Security-Policy",
                        "Strict-Transport-Security",
                        "X-Frame-Options",
                    ) else "bajo"
                    self.findings.append(
                        Finding(
                            tool="cabeceras HTTP",
                            severity=severity,
                            title=f"Cabecera de seguridad ausente: {header}",
                            description=description,
                            evidence=f"Cabecera '{header}' no presente en la respuesta HTTP.",
                            recommendation=(
                                f"Configurar la cabecera HTTP '{header}' en el servidor "
                                f"web o aplicación para mejorar la postura de seguridad."
                            ),
                            phase="reconocimiento",
                        )
                    )

        # Detectar cabeceras que revelan versiones
        server_header = self.http_headers.get("Server", "") or self.http_headers.get("server", "")
        powered_by    = self.http_headers.get("X-Powered-By", "") or self.http_headers.get("x-powered-by", "")

        if server_header:
            version_match = re.search(r"[\d.]+", server_header)
            if version_match:
                self.findings.append(
                    Finding(
                        tool="cabeceras HTTP",
                        severity="bajo",
                        title="Cabecera Server revela versión del software",
                        description=(
                            f"La cabecera 'Server' expone información sobre el software "
                            f"del servidor: {server_header}"
                        ),
                        evidence=f"Server: {server_header}",
                        recommendation=(
                            "Configurar el servidor web para ocultar o generalizar "
                            "la cabecera 'Server'."
                        ),
                        phase="reconocimiento",
                    )
                )

        if powered_by:
            self.findings.append(
                Finding(
                    tool="cabeceras HTTP",
                    severity="bajo",
                    title="Cabecera X-Powered-By expone tecnología del servidor",
                    description=(
                        f"La cabecera 'X-Powered-By' revela información sobre la "
                        f"tecnología usada: {powered_by}"
                    ),
                    evidence=f"X-Powered-By: {powered_by}",
                    recommendation=(
                        "Eliminar o suprimir la cabecera 'X-Powered-By' para "
                        "reducir la superficie de ataque."
                    ),
                    phase="reconocimiento",
                )
            )

        present_count = len(self.security_headers_present)
        missing_count = len(self.security_headers_missing)
        return f"{present_count} cabeceras seguras presentes, {missing_count} ausentes"

    # ─────────────────────────────────────────────────────────────────
    # FASE 2: Descubrimiento
    # ─────────────────────────────────────────────────────────────────

    def phase_discovery(self):
        """Ejecuta la fase de descubrimiento de directorios y archivos."""
        self.console.print()
        self.console.print(Rule("[bold cyan]FASE 2: DESCUBRIMIENTO[/]", style="cyan"))
        self.console.print()

        if not self.tools_available.get("wfuzz", False):
            self.console.print("  [dim]⊘ wfuzz no disponible — omitiendo fase de descubrimiento[/]")
            return

        with self.console.status("[cyan]Ejecutando fuzzing de directorios...[/]", spinner="dots"):
            try:
                summary = self.run_wfuzz()
            except Exception as exc:
                summary = f"Error: {exc}"
                self.console.print(f"  [red]✗ wfuzz falló: {exc}[/]")
                return
        self.console.print(f"  [green]✓[/] wfuzz completado — {summary}")

    def run_wfuzz(self) -> str:
        """
        Ejecuta wfuzz para descubrimiento de directorios.

        CORRECCIÓN v2.0:
        wfuzz 3.x con el printer 'json' escribe un array JSON completo en el
        método footer(), NO una línea JSONL por resultado. El código anterior
        intentaba parsear línea por línea y fallaba porque encontraba una lista
        en el primer elemento (entry.get() sobre una lista → AttributeError).
        Ahora se parsea correctamente como array JSON completo, con fallback
        a JSONL para versiones antiguas o archivos parciales.
        """
        # Buscar wordlist disponible
        wordlist = None
        for wl in WORDLISTS:
            if Path(wl).exists():
                wordlist = wl
                break

        if wordlist is None:
            return "No se encontró ningún diccionario (wordlist)"

        json_path = self.workdir / "discovery" / "wfuzz.json"
        cmd = (
            f"wfuzz -c -z file,{wordlist} --hc 404,403 "
            f"-f {json_path},json {self.target_url}/FUZZ 2>/dev/null"
        )
        stdout, stderr, rc = self.run_cmd(cmd, timeout=300)

        entries = []
        try:
            if json_path.exists():
                raw = json_path.read_text(encoding="utf-8", errors="replace").strip()

                if raw:
                    # ── CORRECCIÓN PRINCIPAL ──────────────────────────────────
                    # wfuzz 3.x escribe un array JSON completo: [{...}, {...}]
                    # Intentar primero parsear como JSON array (comportamiento correcto)
                    try:
                        parsed = json.loads(raw)
                        if isinstance(parsed, list):
                            entries = parsed
                        elif isinstance(parsed, dict):
                            entries = [parsed]
                    except json.JSONDecodeError:
                        # Fallback: intentar como JSONL (versiones antiguas / truncado)
                        for line in raw.splitlines():
                            line = line.strip().lstrip(",").lstrip("[").rstrip("]").rstrip(",")
                            if not line:
                                continue
                            try:
                                obj = json.loads(line)
                                if isinstance(obj, list):
                                    entries.extend(obj)
                                elif isinstance(obj, dict):
                                    entries.append(obj)
                            except json.JSONDecodeError:
                                continue

                # Procesar cada entrada
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue

                    url         = entry.get("url", "")
                    code        = entry.get("code", 0)
                    chars       = entry.get("chars", 0)
                    words       = entry.get("words", 0)
                    lines_count = entry.get("lines", 0)

                    dir_info = {
                        "url":   url,
                        "code":  code,
                        "size":  chars,
                        "words": words,
                        "lines": lines_count,
                    }
                    self.directories_found.append(dir_info)

                    path_part = urlparse(url).path if url else ""

                    if ADMIN_PATTERNS.search(path_part):
                        self.findings.append(
                            Finding(
                                tool="wfuzz",
                                severity="alto",
                                title=f"Panel de administración descubierto: {path_part}",
                                description=(
                                    f"Se encontró un posible panel de administración "
                                    f"accesible en {url} (HTTP {code})."
                                ),
                                evidence=f"URL: {url} — Código: {code} — Tamaño: {chars}",
                                recommendation=(
                                    "Restringir el acceso al panel de administración "
                                    "mediante autenticación fuerte, restricción por IP o VPN."
                                ),
                                phase="descubrimiento",
                            )
                        )
                    elif BACKUP_PATTERNS.search(path_part):
                        self.findings.append(
                            Finding(
                                tool="wfuzz",
                                severity="alto",
                                title=f"Archivo de respaldo expuesto: {path_part}",
                                description=(
                                    f"Se encontró un archivo de respaldo accesible "
                                    f"públicamente en {url}."
                                ),
                                evidence=f"URL: {url} — Código: {code} — Tamaño: {chars}",
                                recommendation=(
                                    "Eliminar archivos de respaldo del servidor web "
                                    "o restringir su acceso."
                                ),
                                phase="descubrimiento",
                            )
                        )
                    elif CONFIG_PATTERNS.search(path_part):
                        self.findings.append(
                            Finding(
                                tool="wfuzz",
                                severity="critico",
                                title=f"Archivo de configuración expuesto: {path_part}",
                                description=(
                                    f"Se encontró un archivo de configuración accesible "
                                    f"en {url}. Puede contener credenciales u otra "
                                    f"información sensible."
                                ),
                                evidence=f"URL: {url} — Código: {code} — Tamaño: {chars}",
                                recommendation=(
                                    "Eliminar o proteger inmediatamente los archivos "
                                    "de configuración expuestos."
                                ),
                                phase="descubrimiento",
                            )
                        )
                    elif SENSITIVE_PATTERNS.search(path_part):
                        self.findings.append(
                            Finding(
                                tool="wfuzz",
                                severity="alto",
                                title=f"Directorio sensible expuesto: {path_part}",
                                description=(
                                    f"Se encontró un directorio de control de versiones "
                                    f"o metadatos accesible en {url}."
                                ),
                                evidence=f"URL: {url} — Código: {code} — Tamaño: {chars}",
                                recommendation=(
                                    "Bloquear el acceso a directorios de metadatos "
                                    "y control de versiones en el servidor web."
                                ),
                                phase="descubrimiento",
                            )
                        )

        except Exception as exc:
            self.console.print(f"  [yellow]⚠  Error procesando wfuzz: {exc}[/]")

        if self.directories_found:
            dt = Table(
                title="Directorios y Archivos Descubiertos",
                box=box.SIMPLE_HEAVY,
                title_style="bold green",
            )
            dt.add_column("Código", justify="center", style="bold")
            dt.add_column("URL", style="cyan")
            dt.add_column("Tamaño", justify="right", style="dim")
            for d in self.directories_found[:30]:
                code_style = "green" if d["code"] == 200 else "yellow"
                dt.add_row(
                    f"[{code_style}]{d['code']}[/]",
                    d["url"],
                    str(d["size"]),
                )
            if len(self.directories_found) > 30:
                dt.add_row("...", f"(+{len(self.directories_found) - 30} más)", "")
            self.console.print(dt)

        return f"{len(self.directories_found)} rutas descubiertas"

    # ─────────────────────────────────────────────────────────────────
    # FASE 3: Evasión
    # ─────────────────────────────────────────────────────────────────

    def phase_evasion(self):
        """
        Fase de evasión: detecta mecanismos de defensa activos y prueba
        técnicas de bypass básicas para determinar la superficie real del objetivo.
        """
        self.console.print()
        self.console.print(Rule("[bold cyan]FASE 3: EVASIÓN Y BYPASS[/]", style="cyan"))
        self.console.print()

        tasks = [
            ("Verificación de bypass de cabeceras WAF",        self._test_waf_header_bypass),
            ("Prueba de codificación de URL (evasión básica)", self._test_url_encoding),
            ("Detección de rate limiting / bloqueo por IP",    self._test_rate_limiting),
            ("Comprobación de cookies de seguridad",           self._test_security_cookies),
        ]

        for desc, func in tasks:
            with self.console.status(f"[cyan]{desc}...[/]", spinner="dots"):
                try:
                    summary = func()
                except Exception as exc:
                    summary = f"Error: {exc}"
            self.console.print(f"  [green]✓[/] {desc} — {summary}")

    def _test_waf_header_bypass(self) -> str:
        """
        Prueba cabeceras de bypass de WAF comunes (X-Forwarded-For, X-Real-IP, etc.)
        Compara el código de respuesta normal con el que se obtiene al inyectar
        cabeceras que pueden engañar a proxies/WAF para confundir el origen.
        """
        if not REQUESTS_AVAILABLE:
            return "Omitido (requests no disponible)"

        self.evasion_results["waf_bypass_tested"] = True
        baseline = self._http_get(self.target_url)
        if baseline is None:
            return "No se pudo establecer respuesta base"

        baseline_len  = len(baseline.content)
        baseline_code = baseline.status_code
        effective     = []

        for extra_headers in WAF_BYPASS_HEADERS:
            resp = self._http_get(self.target_url, headers=extra_headers)
            if resp is None:
                continue
            header_name = list(extra_headers.keys())[0]
            # Si el código cambia o el tamaño difiere significativamente
            if resp.status_code != baseline_code or abs(len(resp.content) - baseline_len) > 200:
                effective.append(header_name)
                self.evasion_results["bypass_headers_effective"].append(header_name)

        if effective:
            self.findings.append(
                Finding(
                    tool="evasión",
                    severity="medio",
                    title="Cabeceras de bypass WAF efectivas detectadas",
                    description=(
                        "Se detectaron cabeceras HTTP que modifican el comportamiento "
                        "del servidor/WAF al spoofear la IP de origen. Esto puede permitir "
                        "a un atacante evadir restricciones basadas en IP."
                    ),
                    evidence=f"Cabeceras efectivas: {', '.join(effective)}",
                    recommendation=(
                        "Validar y normalizar la dirección IP de origen en el servidor "
                        "en lugar de confiar en cabeceras HTTP controladas por el cliente. "
                        "Configurar el WAF para ignorar estas cabeceras en contextos no confiables."
                    ),
                    phase="evasión",
                )
            )
            return f"{len(effective)} cabeceras de bypass efectivas: {', '.join(effective)}"
        return "No se detectaron bypasses de cabeceras efectivos"

    def _test_url_encoding(self) -> str:
        """
        Prueba si el servidor maneja correctamente paths con codificación de URL,
        doble codificación o caracteres especiales — técnicas de evasión comunes.
        """
        if not REQUESTS_AVAILABLE:
            return "Omitido (requests no disponible)"

        self.evasion_results["encoding_tested"] = True
        evasion_paths = [
            "/.",                   # Path traversal trivial
            "/%2e/",                # . codificado
            "/%252e/",              # doble codificación
            "/.%00/",               # null byte
            "//",                   # doble barra
            "/./",                  # punto
        ]

        vulnerable_paths = []
        for path in evasion_paths:
            url = f"{self.target_url}{path}"
            resp = self._http_get(url)
            if resp and resp.status_code not in (400, 404, 403, 500):
                vulnerable_paths.append(f"{path} → {resp.status_code}")

        evasion_file = self.workdir / "evasion" / "encoding_tests.txt"
        evasion_file.write_text(
            "\n".join(vulnerable_paths) if vulnerable_paths else "Sin resultados",
            encoding="utf-8"
        )

        if vulnerable_paths:
            return f"{len(vulnerable_paths)} rutas con codificación especial responden"
        return "Sin rutas vulnerables a evasión por codificación"

    def _test_rate_limiting(self) -> str:
        """
        Detecta si el servidor implementa rate limiting enviando múltiples
        peticiones en ráfaga y observando cambios en el código de respuesta.
        """
        if not REQUESTS_AVAILABLE:
            return "Omitido (requests no disponible)"

        codes = []
        for _ in range(10):
            resp = self._http_get(self.target_url)
            if resp:
                codes.append(resp.status_code)

        if not codes:
            return "No se pudo conectar"

        # Si aparecen 429 (Too Many Requests) o 503, hay rate limiting
        rate_limited = any(c in (429, 503) for c in codes)
        blocked      = codes.count(403) > 5

        if rate_limited:
            self.findings.append(
                Finding(
                    tool="evasión",
                    severity="info",
                    title="Rate limiting activo detectado",
                    description=(
                        "El servidor implementa limitación de velocidad de peticiones "
                        "(rate limiting), lo que dificulta ataques de fuerza bruta."
                    ),
                    evidence=f"Códigos HTTP observados: {set(codes)}",
                    recommendation="Mantener el rate limiting activo y bien configurado.",
                    phase="evasión",
                )
            )
            return "Rate limiting activo (HTTP 429 detectado)"
        elif blocked:
            return "Posible bloqueo por IP tras múltiples peticiones"
        else:
            self.findings.append(
                Finding(
                    tool="evasión",
                    severity="bajo",
                    title="No se detectó rate limiting",
                    description=(
                        "El servidor no parece implementar limitación de velocidad "
                        "de peticiones, lo que facilita ataques de fuerza bruta."
                    ),
                    evidence=f"10 peticiones consecutivas respondieron con: {set(codes)}",
                    recommendation=(
                        "Implementar rate limiting en el servidor o WAF para limitar "
                        "el número de peticiones por IP por unidad de tiempo."
                    ),
                    phase="evasión",
                )
            )
            return "Sin rate limiting detectado"

    def _test_security_cookies(self) -> str:
        """
        Verifica que las cookies de sesión tengan los atributos de seguridad
        HttpOnly, Secure y SameSite correctamente configurados.
        """
        if not REQUESTS_AVAILABLE:
            return "Omitido (requests no disponible)"

        resp = self._http_get(self.target_url)
        if resp is None:
            return "No se pudo conectar"

        insecure_cookies = []
        for cookie in resp.cookies:
            issues = []
            if not cookie.has_nonstandard_attr("HttpOnly") and not cookie._rest.get("HttpOnly"):
                issues.append("sin HttpOnly")
            if not cookie.secure:
                issues.append("sin Secure")
            if not cookie.has_nonstandard_attr("SameSite") and not cookie._rest.get("SameSite"):
                issues.append("sin SameSite")
            if issues:
                insecure_cookies.append(f"{cookie.name}: {', '.join(issues)}")

        if insecure_cookies:
            self.findings.append(
                Finding(
                    tool="evasión",
                    severity="medio",
                    title="Cookies de sesión con atributos de seguridad insuficientes",
                    description=(
                        "Se detectaron cookies sin los atributos de seguridad "
                        "HttpOnly, Secure o SameSite, lo que las hace vulnerables "
                        "a robo mediante XSS o transmisión en texto claro."
                    ),
                    evidence="\n".join(insecure_cookies[:10]),
                    recommendation=(
                        "Configurar todas las cookies de sesión con los atributos "
                        "HttpOnly, Secure y SameSite=Strict o SameSite=Lax."
                    ),
                    phase="evasión",
                )
            )
            return f"{len(insecure_cookies)} cookies inseguras: {'; '.join(insecure_cookies[:3])}"
        return "Cookies de sesión con atributos de seguridad correctos (o sin cookies)"

    # ─────────────────────────────────────────────────────────────────
    # FASE 4: Escaneo de vulnerabilidades
    # ─────────────────────────────────────────────────────────────────

    def phase_vulnscan(self):
        """Ejecuta la fase de escaneo de vulnerabilidades."""
        self.console.print()
        self.console.print(
            Rule("[bold cyan]FASE 4: ESCANEO DE VULNERABILIDADES[/]", style="cyan")
        )
        self.console.print()

        tasks = [
            ("nikto",   "Escaneo Nikto",     self.run_nikto),
            ("sslscan", "Análisis SSL/TLS",  self.run_sslscan),
            ("nuclei",  "Escaneo Nuclei",    self.run_nuclei),
        ]

        for tool_name, desc, func in tasks:
            if not self.tools_available.get(tool_name, False):
                self.console.print(
                    f"  [dim]⊘ {tool_name} no disponible — omitiendo {desc}[/]"
                )
                continue
            if tool_name == "sslscan" and not self.is_https:
                self.console.print(
                    f"  [dim]⊘ {tool_name} omitido — el objetivo no usa HTTPS[/]"
                )
                continue
            with self.console.status(f"[cyan]Ejecutando {desc}...[/]", spinner="dots"):
                try:
                    summary = func()
                except Exception as exc:
                    summary = f"Error: {exc}"
                    self.console.print(f"  [red]✗ {tool_name} falló: {exc}[/]")
                    continue
            self.console.print(f"  [green]✓[/] {tool_name} completado — {summary}")

    def run_nikto(self) -> str:
        """Ejecuta nikto y parsea los resultados."""
        json_path = self.workdir / "vulnscan" / "nikto.json"
        cmd = (
            f"nikto -h {self.target_url} -Format json "
            f"-output {json_path} -Tuning 123457890 -maxtime 300"
        )
        stdout, stderr, rc = self.run_cmd(cmd, timeout=360)

        vuln_count = 0
        try:
            if json_path.exists():
                raw = json_path.read_text(encoding="utf-8", errors="replace")
                entries = []
                try:
                    data = json.loads(raw)
                    if isinstance(data, list):
                        entries = data
                    elif isinstance(data, dict):
                        entries = [data]
                except json.JSONDecodeError:
                    for line in raw.strip().splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

                for entry in entries:
                    vulns = entry.get("vulnerabilities", [])
                    if not isinstance(vulns, list):
                        continue
                    for vuln in vulns:
                        vuln_count += 1
                        msg    = vuln.get("msg", "Sin descripción")
                        osvdb  = vuln.get("OSVDB", vuln.get("id", ""))
                        url_v  = vuln.get("url", "")
                        method = vuln.get("method", "")

                        msg_lower = msg.lower()
                        if any(kw in msg_lower for kw in ("injection", "xss", "rce", "remote code", "execute")):
                            severity = "critico"
                        elif any(kw in msg_lower for kw in ("directory listing", "backup", "source code", "password")):
                            severity = "alto"
                        elif any(kw in msg_lower for kw in ("header", "cookie", "disclosure", "version")):
                            severity = "medio"
                        else:
                            severity = "bajo"

                        self.findings.append(
                            Finding(
                                tool="nikto",
                                severity=severity,
                                title=f"Nikto: {msg[:100]}",
                                description=msg,
                                evidence=f"OSVDB: {osvdb} — URL: {url_v} — Método: {method}",
                                recommendation="Investigar y remediar la vulnerabilidad reportada.",
                                phase="escaneo",
                            )
                        )
        except Exception as exc:
            self.console.print(f"  [yellow]⚠  Error procesando nikto: {exc}[/]")

        return f"{vuln_count} vulnerabilidades encontradas"

    def run_sslscan(self) -> str:
        """Ejecuta sslscan y analiza la configuración SSL/TLS."""
        xml_path = self.workdir / "vulnscan" / "sslscan.xml"
        cmd = f"sslscan --xml={xml_path} {self.target_host}:{self.target_port}"
        stdout, stderr, rc = self.run_cmd(cmd, timeout=120)

        self.ssl_info = {
            "protocols":    [],
            "weak_ciphers": [],
            "cert_subject": "",
            "cert_issuer":  "",
            "cert_expiry":  "",
            "cert_expired": False,
        }

        try:
            if xml_path.exists():
                tree = ET.parse(str(xml_path))
                root = tree.getroot()

                for proto in root.findall(".//protocol"):
                    ptype   = proto.get("type", "")
                    pver    = proto.get("version", "")
                    enabled = proto.get("enabled", "0")
                    if enabled == "1":
                        proto_name = f"{ptype}{pver}"
                        self.ssl_info["protocols"].append(proto_name)
                        if proto_name in ("SSLv2", "SSLv3", "TLSv1.0"):
                            self.findings.append(
                                Finding(
                                    tool="sslscan",
                                    severity="alto",
                                    title=f"Protocolo inseguro habilitado: {proto_name}",
                                    description=(
                                        f"El servidor soporta {proto_name}, que es "
                                        f"considerado inseguro y vulnerable a ataques conocidos."
                                    ),
                                    evidence=f"Protocolo: {proto_name} — Estado: habilitado",
                                    recommendation=(
                                        f"Deshabilitar {proto_name} en la configuración del servidor. "
                                        f"Usar TLSv1.2 o superior."
                                    ),
                                    phase="escaneo",
                                )
                            )

                for cipher in root.findall(".//cipher"):
                    strength = cipher.get("strength", "")
                    name     = cipher.get("cipher", cipher.get("sslversion", ""))
                    if strength in ("weak", "anonymous", "null"):
                        self.ssl_info["weak_ciphers"].append(name)

                if self.ssl_info["weak_ciphers"]:
                    self.findings.append(
                        Finding(
                            tool="sslscan",
                            severity="medio",
                            title="Cifrados SSL/TLS débiles detectados",
                            description=(
                                f"Se encontraron {len(self.ssl_info['weak_ciphers'])} "
                                f"cifrados débiles habilitados en el servidor."
                            ),
                            evidence="Cifrados: " + ", ".join(self.ssl_info["weak_ciphers"][:10]),
                            recommendation="Deshabilitar cifrados débiles y usar solo AES-GCM, ChaCha20.",
                            phase="escaneo",
                        )
                    )

                cert = root.find(".//certificate")
                if cert is not None:
                    subj = cert.find(".//subject")
                    if subj is not None:
                        self.ssl_info["cert_subject"] = subj.text or subj.get("value", "")
                    issuer = cert.find(".//issuer")
                    if issuer is not None:
                        self.ssl_info["cert_issuer"] = issuer.text or issuer.get("value", "")
                    expiry = cert.find(".//not-valid-after")
                    if expiry is not None:
                        self.ssl_info["cert_expiry"] = expiry.text or expiry.get("value", "")
                    expired = cert.find(".//expired")
                    if expired is not None:
                        is_expired = expired.text or expired.get("value", "")
                        if is_expired.lower() in ("true", "1", "yes"):
                            self.ssl_info["cert_expired"] = True
                            self.findings.append(
                                Finding(
                                    tool="sslscan",
                                    severity="alto",
                                    title="Certificado SSL expirado",
                                    description="El certificado SSL/TLS del servidor ha expirado.",
                                    evidence=f"Expiración: {self.ssl_info['cert_expiry']}",
                                    recommendation="Renovar inmediatamente el certificado SSL/TLS.",
                                    phase="escaneo",
                                )
                            )
        except ET.ParseError as exc:
            self.console.print(f"  [yellow]⚠  Error parseando XML de sslscan: {exc}[/]")
        except Exception as exc:
            self.console.print(f"  [yellow]⚠  Error procesando sslscan: {exc}[/]")

        protocols_str = ", ".join(self.ssl_info["protocols"]) if self.ssl_info["protocols"] else "ninguno"
        return f"Protocolos: {protocols_str} — {len(self.ssl_info['weak_ciphers'])} cifrados débiles"

    def run_nuclei(self) -> str:
        """Ejecuta nuclei y parsea los resultados JSONL."""
        jsonl_path = self.workdir / "vulnscan" / "nuclei.jsonl"
        cmd = (
            f"nuclei -u {self.target_url} -severity medium,high,critical "
            f"-timeout 10 -retries 1 -jsonl -o {jsonl_path} -silent"
        )
        stdout, stderr, rc = self.run_cmd(cmd, timeout=600)

        vuln_count = 0
        try:
            if jsonl_path.exists():
                raw = jsonl_path.read_text(encoding="utf-8", errors="replace")
                for line in raw.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    vuln_count += 1
                    template_id   = entry.get("template-id", "desconocido")
                    info          = entry.get("info", {})
                    name          = info.get("name", template_id)
                    raw_severity  = info.get("severity", "medium").lower()
                    description   = info.get("description", "")
                    matched_at    = entry.get("matched-at", "")

                    severity_map = {
                        "critical": "critico",
                        "high":     "alto",
                        "medium":   "medio",
                        "low":      "bajo",
                        "info":     "info",
                    }
                    severity = severity_map.get(raw_severity, "medio")
                    self.nuclei_results.append({
                        "template":   template_id,
                        "name":       name,
                        "severity":   severity,
                        "matched_at": matched_at,
                    })
                    self.findings.append(
                        Finding(
                            tool="nuclei",
                            severity=severity,
                            title=f"Nuclei: {name}",
                            description=description or f"Vulnerabilidad detectada: {name}",
                            evidence=f"Template: {template_id} — URL: {matched_at}",
                            recommendation=(
                                "Investigar la vulnerabilidad y aplicar los parches "
                                "o mitigaciones correspondientes."
                            ),
                            phase="escaneo",
                        )
                    )
        except Exception as exc:
            self.console.print(f"  [yellow]⚠  Error procesando nuclei: {exc}[/]")

        return f"{vuln_count} vulnerabilidades detectadas"

    # ─────────────────────────────────────────────────────────────────
    # FASE 5: Recopilación de información
    # ─────────────────────────────────────────────────────────────────

    def phase_collection(self):
        """
        Fase de recopilación: extrae información sensible del objetivo como
        emails, endpoints de APIs, comentarios HTML, robots.txt, sitemap.xml
        y metadatos de archivos descargables.
        """
        self.console.print()
        self.console.print(Rule("[bold cyan]FASE 5: RECOPILACIÓN DE INFORMACIÓN[/]", style="cyan"))
        self.console.print()

        tasks = [
            ("Extracción de emails y endpoints JS",        self._collect_page_info),
            ("Análisis de robots.txt y sitemap.xml",       self._collect_robots_sitemap),
            ("Prueba de LFI / Path Traversal básico",      self._test_lfi),
            ("Detección de XSS reflejado (básico)",        self._test_xss_basic),
        ]

        for desc, func in tasks:
            with self.console.status(f"[cyan]{desc}...[/]", spinner="dots"):
                try:
                    summary = func()
                except Exception as exc:
                    summary = f"Error: {exc}"
            self.console.print(f"  [green]✓[/] {desc} — {summary}")

    def _collect_page_info(self) -> str:
        """Extrae emails, comentarios HTML y endpoints JS de la página principal."""
        if not REQUESTS_AVAILABLE:
            return "Omitido (requests no disponible)"

        resp = self._http_get(self.target_url)
        if resp is None:
            return "No se pudo obtener la página"

        content = resp.text

        # Emails
        emails = set(re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            content
        ))
        for email in emails:
            if email not in self.metadata_results["emails"]:
                self.metadata_results["emails"].append(email)

        # Endpoints JS (fetch, XMLHttpRequest, src de scripts)
        js_urls = set(re.findall(
            r"""(?:fetch|axios\.get|axios\.post|XMLHttpRequest|\.open)\s*\(\s*['"`]([^'"`]+)['"`]""",
            content
        ))
        js_urls |= set(re.findall(r"""<script[^>]+src=['"]([^'"]+)['"]""", content))
        for url in js_urls:
            if url not in self.metadata_results["js_endpoints"]:
                self.metadata_results["js_endpoints"].append(url[:300])

        # Comentarios HTML
        comments = re.findall(r"<!--(.*?)-->", content, re.DOTALL)
        interesting_comments = [
            c.strip()[:200] for c in comments
            if any(kw in c.lower() for kw in ("password", "todo", "fixme", "api", "key", "secret", "token"))
        ]
        self.metadata_results["comments"].extend(interesting_comments[:10])

        if interesting_comments:
            self.findings.append(
                Finding(
                    tool="recopilación",
                    severity="medio",
                    title="Comentarios HTML con información sensible detectados",
                    description=(
                        "Se encontraron comentarios HTML que contienen palabras clave "
                        "sensibles como 'password', 'api', 'key', 'token', etc."
                    ),
                    evidence="\n".join(interesting_comments[:3]),
                    recommendation=(
                        "Eliminar todos los comentarios HTML que contengan información "
                        "sensible antes de desplegar en producción."
                    ),
                    phase="recopilación",
                )
            )

        if emails:
            self.findings.append(
                Finding(
                    tool="recopilación",
                    severity="info",
                    title=f"Emails expuestos en el código fuente ({len(emails)})",
                    description=(
                        "Se encontraron direcciones de correo electrónico en el código "
                        "fuente de la página, lo que puede facilitar ataques de phishing o spam."
                    ),
                    evidence=", ".join(list(emails)[:10]),
                    recommendation=(
                        "Evaluar si es necesario exponer las direcciones de email. "
                        "Considerar el uso de formularios de contacto en su lugar."
                    ),
                    phase="recopilación",
                )
            )

        collection_file = self.workdir / "collection" / "page_info.txt"
        with open(collection_file, "w", encoding="utf-8") as f:
            f.write(f"=== EMAILS ({len(emails)}) ===\n")
            f.write("\n".join(self.metadata_results["emails"]) + "\n\n")
            f.write(f"=== ENDPOINTS JS ({len(js_urls)}) ===\n")
            f.write("\n".join(self.metadata_results["js_endpoints"]) + "\n\n")
            f.write(f"=== COMENTARIOS SENSIBLES ({len(interesting_comments)}) ===\n")
            f.write("\n".join(interesting_comments) + "\n")

        return (
            f"{len(emails)} emails, "
            f"{len(js_urls)} endpoints JS, "
            f"{len(interesting_comments)} comentarios sensibles"
        )

    def _collect_robots_sitemap(self) -> str:
        """Descarga y analiza robots.txt y sitemap.xml."""
        found_items = 0

        for path in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]:
            url  = f"{self.target_url}{path}"
            resp = self._http_get(url) if REQUESTS_AVAILABLE else None

            if resp is None:
                # Fallback con curl
                if self.tools_available.get("curl", False):
                    cmd  = f"curl -sL --max-time 10 {url}"
                    out, _, rc = self.run_cmd(cmd, timeout=15)
                    if rc == 0 and out.strip():
                        resp_text = out
                    else:
                        continue
                else:
                    continue
            else:
                if resp.status_code != 200:
                    continue
                resp_text = resp.text

            # Guardar archivo
            safe_name = path.strip("/").replace("/", "_")
            out_file  = self.workdir / "collection" / safe_name
            out_file.write_text(resp_text[:50000], encoding="utf-8")
            found_items += 1

            if "robots.txt" in path:
                disallowed = re.findall(r"^Disallow:\s*(.+)$", resp_text, re.MULTILINE | re.IGNORECASE)
                self.metadata_results["robots_entries"] = disallowed[:50]
                if disallowed:
                    self.findings.append(
                        Finding(
                            tool="recopilación",
                            severity="info",
                            title=f"robots.txt revela {len(disallowed)} rutas restringidas",
                            description=(
                                "El archivo robots.txt lista rutas que el webmaster "
                                "no quiere indexar — estas pueden ser de alto valor para un atacante."
                            ),
                            evidence="Rutas: " + ", ".join(disallowed[:10]),
                            recommendation=(
                                "No confiar en robots.txt como mecanismo de seguridad. "
                                "Implementar autenticación y control de acceso real en rutas sensibles."
                            ),
                            phase="recopilación",
                        )
                    )
            elif "sitemap" in path:
                urls = re.findall(r"<loc>(.*?)</loc>", resp_text)
                self.metadata_results["sitemap_urls"] = urls[:100]

        return f"{found_items} archivos de mapeo obtenidos"

    def _test_lfi(self) -> str:
        """
        Prueba básica de LFI (Local File Inclusion) en parámetros GET descubiertos.
        Solo detecta, no explota.
        """
        if not REQUESTS_AVAILABLE:
            return "Omitido (requests no disponible)"

        # Recolectar URLs con parámetros GET
        target_params = []
        for d in self.directories_found:
            url = d.get("url", "")
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name in params:
                    target_params.append((url, param_name))

        # También probar parámetros comunes en la URL base
        common_params = ["page", "file", "path", "include", "load", "template", "view", "lang"]
        for param in common_params:
            target_params.append((f"{self.target_url}/?{param}=index", param))

        vulnerable_lfi = []
        lfi_signatures = ["root:x:", "[boot loader]", "bin/bash", "etc/shadow", "DOCUMENT_ROOT"]

        for base_url, param_name in target_params[:20]:  # Limitar pruebas
            for payload in LFI_PAYLOADS[:3]:
                test_url = re.sub(
                    rf"({re.escape(param_name)}=)[^&]*",
                    rf"\g<1>{quote(payload)}",
                    base_url
                )
                if test_url == base_url:
                    # Construir URL con parámetro si no existía
                    sep = "&" if "?" in base_url else "?"
                    test_url = f"{base_url}{sep}{param_name}={quote(payload)}"

                resp = self._http_get(test_url)
                if resp and any(sig in resp.text for sig in lfi_signatures):
                    vulnerable_lfi.append(f"{param_name}: {payload}")
                    self.evasion_results["lfi_vulnerable"].append(test_url)

        if vulnerable_lfi:
            self.findings.append(
                Finding(
                    tool="recopilación",
                    severity="critico",
                    title="Vulnerabilidad LFI (Local File Inclusion) detectada",
                    description=(
                        "Se detectaron parámetros vulnerables a inclusión de archivos locales. "
                        "Un atacante podría leer archivos sensibles del sistema como /etc/passwd."
                    ),
                    evidence="\n".join(vulnerable_lfi[:5]),
                    recommendation=(
                        "Validar y sanitizar todas las entradas de usuario que se usen "
                        "para incluir archivos. Usar listas blancas de rutas permitidas. "
                        "Deshabilitar allow_url_include en PHP."
                    ),
                    phase="recopilación",
                )
            )
            return f"¡{len(vulnerable_lfi)} vectores LFI detectados!"
        return "Sin vulnerabilidades LFI detectadas"

    def _test_xss_basic(self) -> str:
        """
        Prueba básica de XSS reflejado buscando si los payloads se reflejan
        sin sanitizar en la respuesta. Solo detecta reflexión, no confirma ejecución.
        """
        if not REQUESTS_AVAILABLE:
            return "Omitido (requests no disponible)"

        reflected_xss = []
        # Recopilar endpoints con parámetros
        test_targets = []
        for d in self.directories_found[:20]:
            url = d.get("url", "")
            if "?" in url:
                test_targets.append(url)

        if not test_targets:
            # Probar la URL base con parámetro de búsqueda común
            for param in ["q", "search", "s", "query", "keyword"]:
                test_targets.append(f"{self.target_url}/?{param}=test")

        for base_url in test_targets[:10]:
            for payload in XSS_PAYLOADS[:2]:
                # Inyectar payload en todos los parámetros
                parsed = urlparse(base_url)
                params = parse_qs(parsed.query)
                for param_name in list(params.keys())[:3]:
                    test_url = re.sub(
                        rf"({re.escape(param_name)}=)[^&]*",
                        rf"\g<1>{quote(payload)}",
                        base_url
                    )
                    resp = self._http_get(test_url)
                    if resp and payload in resp.text:
                        reflected_xss.append(f"{param_name}: {payload[:50]}")
                        self.evasion_results["xss_reflected"].append(test_url)

        xss_file = self.workdir / "collection" / "xss_results.txt"
        xss_file.write_text(
            "\n".join(reflected_xss) if reflected_xss else "Sin resultados",
            encoding="utf-8"
        )

        if reflected_xss:
            self.findings.append(
                Finding(
                    tool="recopilación",
                    severity="alto",
                    title="XSS Reflejado potencial detectado",
                    description=(
                        "Se detectaron parámetros que reflejan payloads XSS sin sanitizar "
                        "en la respuesta HTTP. Esto puede indicar una vulnerabilidad XSS reflejado."
                    ),
                    evidence="\n".join(reflected_xss[:5]),
                    recommendation=(
                        "Sanitizar y codificar todas las salidas que incluyan datos del usuario. "
                        "Implementar Content-Security-Policy. "
                        "Usar funciones de escape específicas del contexto (HTML, JS, URL)."
                    ),
                    phase="recopilación",
                )
            )
            return f"¡{len(reflected_xss)} posibles XSS reflejados detectados!"
        return "Sin XSS reflejados detectados"

    # ─────────────────────────────────────────────────────────────────
    # FASE 6: Explotación
    # ─────────────────────────────────────────────────────────────────

    def phase_exploit(self):
        """Ejecuta la fase de pruebas de explotación (SQLMap)."""
        self.console.print()
        self.console.print(Rule("[bold cyan]FASE 6: EXPLOTACIÓN[/]", style="cyan"))
        self.console.print()

        if not self.tools_available.get("sqlmap", False):
            self.console.print(
                "  [dim]⊘ sqlmap no disponible — omitiendo fase de explotación[/]"
            )
            return

        with self.console.status(
            "[cyan]Ejecutando pruebas de inyección SQL...[/]", spinner="dots"
        ):
            try:
                summary = self.run_sqlmap()
            except Exception as exc:
                summary = f"Error: {exc}"
                self.console.print(f"  [red]✗ sqlmap falló: {exc}[/]")
                return
        self.console.print(f"  [green]✓[/] sqlmap completado — {summary}")

    def run_sqlmap(self) -> str:
        """Ejecuta sqlmap con descubrimiento automático de formularios."""
        output_dir = self.workdir / "exploit" / "sqlmap"
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = (
            f"sqlmap -u {self.target_url} --forms --crawl=2 --batch "
            f"--level=2 --risk=2 --output-dir={output_dir} "
            f"--random-agent --threads=4"
        )
        stdout, stderr, rc = self.run_cmd(cmd, timeout=600)

        # Probar URLs con parámetros descubiertos
        urls_with_params = [
            d.get("url", "")
            for d in self.directories_found
            if "?" in d.get("url", "")
        ]
        for param_url in urls_with_params[:5]:
            extra_cmd = (
                f"sqlmap -u '{param_url}' --batch --level=2 --risk=2 "
                f"--output-dir={output_dir} --random-agent --threads=4"
            )
            self.run_cmd(extra_cmd, timeout=300)

        injection_count = 0
        try:
            for log_file in output_dir.rglob("log"):
                if not log_file.is_file():
                    continue
                content = log_file.read_text(encoding="utf-8", errors="replace")
                if not content.strip():
                    continue

                injection_blocks = re.split(r"---\n", content)
                for block in injection_blocks:
                    if "Parameter:" in block or "injectable" in block.lower():
                        injection_count += 1
                        param_match = re.search(r"Parameter:\s*(.+)", block)
                        type_match  = re.search(r"Type:\s*(.+)", block)
                        title_match = re.search(r"Title:\s*(.+)", block)

                        param_name = param_match.group(1).strip() if param_match else "desconocido"
                        inj_type   = type_match.group(1).strip()  if type_match  else ""
                        inj_title  = title_match.group(1).strip() if title_match else "Inyección SQL"

                        result_str = f"Parámetro: {param_name} — Tipo: {inj_type} — {inj_title}"
                        self.sqlmap_results.append(result_str)

                        self.findings.append(
                            Finding(
                                tool="sqlmap",
                                severity="critico",
                                title=f"Inyección SQL: {param_name}",
                                description=(
                                    f"Se detectó una vulnerabilidad de inyección SQL en el "
                                    f"parámetro '{param_name}'. Tipo: {inj_type}. {inj_title}"
                                ),
                                evidence=block[:500],
                                recommendation=(
                                    "Utilizar consultas parametrizadas (prepared statements). "
                                    "Validar y sanitizar todas las entradas del usuario. "
                                    "Implementar un WAF como capa adicional de protección."
                                ),
                                phase="explotación",
                            )
                        )
        except Exception as exc:
            self.console.print(f"  [yellow]⚠  Error procesando sqlmap: {exc}[/]")

        if injection_count > 0:
            return f"¡{injection_count} inyecciones SQL encontradas!"
        return "No se encontraron inyecciones SQL"

    # ─────────────────────────────────────────────────────────────────
    # FASE 7: Generación de informe
    # ─────────────────────────────────────────────────────────────────

    def generate_report(self):
        """Genera el informe final de la auditoría."""
        self.console.print()
        self.console.print(Rule("[bold cyan]FASE 7: GENERACIÓN DE INFORME[/]", style="cyan"))
        self.console.print()

        severity_counts = {"critico": 0, "alto": 0, "medio": 0, "bajo": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Nivel de riesgo general
        if severity_counts["critico"] > 0:
            risk_level = "CRÍTICO"
            risk_color = "bold red"
        elif severity_counts["alto"] > 0:
            risk_level = "ALTO"
            risk_color = "red"
        elif severity_counts["medio"] > 0:
            risk_level = "MEDIO"
            risk_color = "yellow"
        elif severity_counts["bajo"] > 0:
            risk_level = "BAJO"
            risk_color = "blue"
        else:
            risk_level = "INFORMATIVO"
            risk_color = "green"

        self.console.print(
            Panel(
                f"[{risk_color}]Nivel de Riesgo General: {risk_level}[/]",
                title="[bold]Resultado de la Auditoría[/]",
                border_style=risk_color.replace("bold ", ""),
            )
        )

        summary_table = Table(title="Resumen de Hallazgos", box=box.ROUNDED, title_style="bold")
        summary_table.add_column("Severidad", style="bold")
        summary_table.add_column("Cantidad", justify="center")
        for sev, count in severity_counts.items():
            style = SEVERITY_MAP.get(sev, "white")
            summary_table.add_row(f"[{style}]{sev.upper()}[/]", str(count))
        summary_table.add_row("[bold]TOTAL[/]", f"[bold]{sum(severity_counts.values())}[/]")
        self.console.print(summary_table)

        if self.findings:
            self.console.print()
            detail_table = Table(
                title="Detalle de Hallazgos",
                box=box.ROUNDED,
                title_style="bold",
                show_lines=True,
            )
            detail_table.add_column("#",           justify="center", width=4)
            detail_table.add_column("Sev.",        justify="center", width=8)
            detail_table.add_column("Herramienta", width=14)
            detail_table.add_column("Fase",        width=12)
            detail_table.add_column("Título",      min_width=35)
            for i, f in enumerate(self.findings, 1):
                style = SEVERITY_MAP.get(f.severity, "white")
                detail_table.add_row(
                    str(i),
                    f"[{style}]{f.severity.upper()}[/]",
                    f.tool,
                    f.phase,
                    f.title[:80],
                )
            self.console.print(detail_table)

        # Generar informe HTML
        report_path = self._generate_html_report(severity_counts, risk_level)

        if report_path:
            self.console.print(f"\n[bold green]📄 Informe generado:[/] {report_path}")
            home_report = Path.home() / report_path.name
            try:
                shutil.copy2(str(report_path), str(home_report))
                self.console.print(f"[dim]Copia en: {home_report}[/]")
            except Exception:
                pass
            try:
                if Confirm.ask("\n[cyan]¿Deseas abrir el informe en el navegador?[/]"):
                    subprocess.Popen(
                        ["xdg-open", str(report_path)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
            except Exception:
                pass

    def _generate_html_report(self, severity_counts: dict, risk_level: str) -> Optional[Path]:
        """Genera el informe HTML usando Jinja2 o un fallback embebido."""
        date_str    = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"WebAudit_Report_{self.target_host}_{date_str}.html"
        report_path = self.workdir / report_name

        duration = ""
        if self.start_time:
            duration = str(datetime.now() - self.start_time).split(".")[0]

        template_vars = {
            "target_url":              self.target_url,
            "target_host":             self.target_host,
            "target_ip":               self.target_ip,
            "target_port":             self.target_port,
            "is_https":                self.is_https,
            "scan_date":               datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration":                duration,
            "risk_level":              risk_level,
            "severity_counts":         severity_counts,
            "total_findings":          sum(severity_counts.values()),
            "findings":                [asdict(f) for f in self.findings],
            "open_ports":              self.open_ports,
            "technologies":            self.technologies,
            "waf_detected":            self.waf_detected,
            "directories_found":       self.directories_found[:50],
            "ssl_info":                self.ssl_info,
            "whois_info":              self.whois_info[:2000] if self.whois_info else "",
            "dns_info":                self.dns_info,
            "http_headers":            dict(list(self.http_headers.items())[:30]),
            "security_headers_present": self.security_headers_present,
            "security_headers_missing": self.security_headers_missing,
            "nuclei_results":          self.nuclei_results,
            "sqlmap_results":          self.sqlmap_results,
            "metadata_results":        self.metadata_results,
            "evasion_results":         self.evasion_results,
        }

        html_content = None
        if JINJA2_AVAILABLE and Template is not None:
            script_dir    = Path(__file__).parent
            template_path = script_dir / "report_template.html"
            if template_path.exists():
                try:
                    tmpl_raw    = template_path.read_text(encoding="utf-8")
                    tmpl        = Template(tmpl_raw)
                    html_content = tmpl.render(**template_vars)
                except Exception as exc:
                    self.console.print(f"  [yellow]⚠  Error con plantilla externa: {exc}[/]")

        if html_content is None:
            html_content = self._build_html_report(template_vars)

        try:
            report_path.write_text(html_content, encoding="utf-8")
            return report_path
        except Exception as exc:
            self.console.print(f"  [red]✗ Error guardando informe: {exc}[/]")
            return None

    @staticmethod
    def _build_html_report(v: dict) -> str:
        """Genera el informe HTML completo en español."""
        sev_colors = {
            "critico": "#e74c3c",
            "alto":    "#e67e22",
            "medio":   "#f1c40f",
            "bajo":    "#3498db",
            "info":    "#95a5a6",
        }
        risk_colors = {
            "CRÍTICO":     "#e74c3c",
            "ALTO":        "#e67e22",
            "MEDIO":       "#f1c40f",
            "BAJO":        "#3498db",
            "INFORMATIVO": "#2ecc71",
        }
        risk_bg = risk_colors.get(v["risk_level"], "#95a5a6")

        # ── Hallazgos ──
        findings_rows = ""
        for i, f in enumerate(v["findings"], 1):
            sev   = f["severity"]
            color = sev_colors.get(sev, "#95a5a6")
            evidence_escaped    = f["evidence"].replace("<", "&lt;").replace(">", "&gt;")
            description_escaped = f["description"].replace("<", "&lt;").replace(">", "&gt;")
            recommendation_escaped = f["recommendation"].replace("<", "&lt;").replace(">", "&gt;")
            findings_rows += f"""
            <tr>
                <td>{i}</td>
                <td><span class="badge" style="background:{color}">{sev.upper()}</span></td>
                <td>{f["tool"]}</td>
                <td><em>{f.get("phase","")}</em></td>
                <td><strong>{f["title"][:120]}</strong></td>
                <td class="mono">{description_escaped[:300]}</td>
                <td class="mono">{evidence_escaped[:200]}</td>
                <td>{recommendation_escaped[:300]}</td>
            </tr>"""

        # ── Puertos ──
        ports_rows = ""
        for p in v["open_ports"]:
            ports_rows += f"""
            <tr>
                <td><strong>{p["port"]}</strong></td>
                <td>{p["protocol"]}</td>
                <td>{p["service"]}</td>
                <td class="mono">{p["version"]}</td>
            </tr>"""

        # ── Barras de severidad ──
        sc = v["severity_counts"]
        max_count = max(sc.values()) if any(sc.values()) else 1
        summary_bars = ""
        for sev, count in sc.items():
            color = sev_colors.get(sev, "#95a5a6")
            width = int((count / max_count) * 100) if max_count > 0 else 0
            summary_bars += f"""
            <div class="bar-row">
                <span class="bar-label" style="color:{color}">{sev.upper()}</span>
                <span class="bar-count">{count}</span>
                <div class="bar-track">
                    <div class="bar-fill" style="width:{width}%;background:{color}"></div>
                </div>
            </div>"""

        # ── Tecnologías ──
        tech_tags = "".join(
            f'<span class="tech-tag">{t}</span>' for t in v["technologies"]
        ) or '<span class="dim">Ninguna detectada</span>'

        # ── Directorios ──
        dirs_rows = ""
        for d in v["directories_found"][:50]:
            code_color = "#2ecc71" if d["code"] == 200 else "#f39c12"
            dirs_rows += f"""
            <tr>
                <td style="color:{code_color};font-weight:bold">{d["code"]}</td>
                <td class="mono"><a href="{d["url"]}" target="_blank" style="color:#00d4ff">{d["url"]}</a></td>
                <td>{d["size"]}</td>
            </tr>"""

        # ── Cabeceras HTTP ──
        headers_rows = ""
        for h, val in v["http_headers"].items():
            is_security = h in SECURITY_HEADERS
            style = "color:#2ecc71" if is_security else ""
            val_escaped = str(val).replace("<", "&lt;").replace(">", "&gt;")
            headers_rows += f"""
            <tr>
                <td style="{style}">{h}</td>
                <td class="mono">{val_escaped[:200]}</td>
            </tr>"""

        sec_present_tags = "".join(
            f'<span class="badge" style="background:#2ecc71">{h}</span> '
            for h in v["security_headers_present"]
        ) or '<em class="dim">Ninguna</em>'

        sec_missing_tags = "".join(
            f'<span class="badge" style="background:#e74c3c">{h}</span> '
            for h in v["security_headers_missing"]
        ) or '<em class="dim">Todas presentes ✓</em>'

        # ── Metadatos ──
        emails_list = "<br>".join(v["metadata_results"]["emails"][:20]) or "Ninguno"
        robots_list = "<br>".join(v["metadata_results"]["robots_entries"][:20]) or "No disponible"
        comments_list = "".join(
            f'<div class="code-block">{c[:300]}</div>' for c in v["metadata_results"]["comments"]
        ) or "Sin comentarios sensibles"

        # ── Evasión ──
        lfi_list = "<br>".join(v["evasion_results"]["lfi_vulnerable"][:10]) or "No detectado"
        xss_list = "<br>".join(v["evasion_results"]["xss_reflected"][:10]) or "No detectado"
        bypass_list = "<br>".join(v["evasion_results"]["bypass_headers_effective"]) or "Ninguno"

        # ── Informe WHOIS ──
        whois_display = v["whois_info"].replace("<", "&lt;").replace(">", "&gt;")[:3000] if v["whois_info"] else "No disponible"

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAudit Pro — Informe de Auditoría de {v["target_host"]}</title>
    <meta name="description" content="Informe de auditoría de seguridad web generado por WebAudit Pro v2.0">
    <style>
        :root {{
            --bg:      #0d1117;
            --surface: #161b22;
            --card:    #21262d;
            --border:  #30363d;
            --accent:  #00d4ff;
            --text:    #e6edf3;
            --dim:     #8b949e;
        }}
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 24px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}

        /* ── Header ── */
        .report-header {{
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, #0d1117 0%, #1a2332 50%, #0d1117 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        .report-header h1 {{
            font-size: 2.4em;
            color: var(--accent);
            text-shadow: 0 0 20px #00d4ff44;
            margin-bottom: 8px;
        }}
        .report-header .subtitle {{ color: var(--dim); font-size: 1.05em; }}
        .report-header .meta {{
            display: flex; justify-content: center; gap: 30px;
            margin-top: 20px; flex-wrap: wrap;
        }}
        .meta-item {{ color: var(--dim); font-size: 0.9em; }}
        .meta-item strong {{ color: var(--text); }}

        /* ── Risk Badge ── */
        .risk-badge {{
            text-align: center; padding: 24px;
            background: {risk_bg}15;
            border: 2px solid {risk_bg};
            border-radius: 12px;
            font-size: 1.8em;
            font-weight: 900;
            color: {risk_bg};
            margin: 24px 0;
            letter-spacing: 2px;
            text-shadow: 0 0 20px {risk_bg}66;
        }}

        /* ── Sections ── */
        .section {{ margin: 30px 0; }}
        .section-title {{
            font-size: 1.4em;
            color: var(--accent);
            border-bottom: 2px solid var(--accent);
            padding-bottom: 10px;
            margin-bottom: 20px;
            display: flex; align-items: center; gap: 10px;
        }}

        /* ── Info Grid ── */
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }}
        .info-card {{
            background: var(--card);
            padding: 16px 20px;
            border-radius: 10px;
            border-left: 4px solid var(--accent);
        }}
        .info-card .label {{ color: var(--dim); font-size: 0.82em; text-transform: uppercase; letter-spacing: 1px; }}
        .info-card .value {{ font-size: 1.1em; font-weight: bold; margin-top: 4px; word-break: break-all; }}

        /* ── Bars ── */
        .bar-row {{ display:flex; align-items:center; margin:8px 0; gap:10px; }}
        .bar-label {{ width:80px; font-weight:bold; font-size:0.85em; }}
        .bar-count {{ width:35px; text-align:right; font-size:0.9em; color:var(--dim); }}
        .bar-track {{ flex:1; background:var(--card); border-radius:4px; height:18px; overflow:hidden; }}
        .bar-fill   {{ height:100%; border-radius:4px; transition:width 0.5s; }}

        /* ── Tables ── */
        .table-wrap {{ overflow-x:auto; border-radius:10px; border:1px solid var(--border); }}
        table {{ width:100%; border-collapse:collapse; background:var(--surface); }}
        thead {{ background: #0f3460; }}
        th {{ color:var(--accent); padding:12px 10px; text-align:left; font-size:0.85em; white-space:nowrap; }}
        td {{ padding:10px; border-bottom:1px solid var(--border); font-size:0.88em; vertical-align:top; }}
        tr:hover {{ background:var(--card); }}
        tr:last-child td {{ border-bottom:none; }}

        /* ── Misc ── */
        .badge {{
            display:inline-block;
            padding:2px 10px;
            border-radius:20px;
            font-weight:bold;
            font-size:0.78em;
            color:#fff;
            white-space:nowrap;
        }}
        .tech-tag {{
            display:inline-block;
            background:var(--card);
            padding:4px 12px;
            border-radius:20px;
            font-size:0.82em;
            border:1px solid var(--border);
            margin:3px;
        }}
        .mono {{ font-family:monospace; font-size:0.82em; word-break:break-all; }}
        .dim  {{ color:var(--dim); }}
        .code-block {{
            background:var(--card);
            border:1px solid var(--border);
            border-radius:6px;
            padding:10px;
            margin:6px 0;
            font-family:monospace;
            font-size:0.82em;
            white-space:pre-wrap;
            word-break:break-all;
        }}
        .whois-box {{
            background:var(--card);
            border:1px solid var(--border);
            border-radius:8px;
            padding:16px;
            font-family:monospace;
            font-size:0.78em;
            white-space:pre-wrap;
            overflow-x:auto;
            max-height:300px;
            overflow-y:auto;
            color:var(--dim);
        }}
        .toc {{
            background:var(--card);
            border:1px solid var(--border);
            border-radius:10px;
            padding:20px;
            margin:20px 0;
        }}
        .toc ul {{ list-style:none; display:flex; flex-wrap:wrap; gap:8px; }}
        .toc a {{ color:var(--accent); text-decoration:none; font-size:0.9em; }}
        .toc a:hover {{ text-decoration:underline; }}
        .footer {{
            text-align:center;
            color:var(--dim);
            margin-top:50px;
            padding:24px;
            border-top:1px solid var(--border);
            font-size:0.85em;
        }}
        @media (max-width:768px) {{
            body {{ padding:12px; }}
            .report-header h1 {{ font-size:1.6em; }}
            .risk-badge {{ font-size:1.2em; }}
        }}
    </style>
</head>
<body>
<div class="container">

    <!-- ── CABECERA ── -->
    <div class="report-header">
        <h1>🛡️ WebAudit Pro — Informe de Auditoría de Seguridad</h1>
        <p class="subtitle">Análisis automatizado de seguridad web</p>
        <div class="meta">
            <div class="meta-item">📅 <strong>{v["scan_date"]}</strong></div>
            <div class="meta-item">⏱️ Duración: <strong>{v["duration"]}</strong></div>
            <div class="meta-item">🎯 Objetivo: <strong>{v["target_url"]}</strong></div>
            <div class="meta-item">📊 Hallazgos: <strong>{v["total_findings"]}</strong></div>
        </div>
    </div>

    <!-- ── ÍNDICE ── -->
    <div class="toc">
        <strong style="color:var(--accent)">📋 Índice de Contenidos</strong>
        <ul>
            <li><a href="#objetivo">1. Información del Objetivo</a></li>
            <li><a href="#riesgo">2. Nivel de Riesgo</a></li>
            <li><a href="#resumen">3. Resumen de Hallazgos</a></li>
            <li><a href="#hallazgos">4. Detalle de Hallazgos</a></li>
            <li><a href="#puertos">5. Puertos y Servicios</a></li>
            <li><a href="#tecnologias">6. Tecnologías Detectadas</a></li>
            <li><a href="#cabeceras">7. Cabeceras HTTP</a></li>
            <li><a href="#directorios">8. Directorios Descubiertos</a></li>
            <li><a href="#evasion">9. Resultados de Evasión</a></li>
            <li><a href="#metadatos">10. Recopilación de Información</a></li>
            <li><a href="#whois">11. Información WHOIS</a></li>
        </ul>
    </div>

    <!-- ── 1. OBJETIVO ── -->
    <div class="section" id="objetivo">
        <h2 class="section-title">📋 1. Información del Objetivo</h2>
        <div class="info-grid">
            <div class="info-card"><div class="label">URL</div><div class="value">{v["target_url"]}</div></div>
            <div class="info-card"><div class="label">Host</div><div class="value">{v["target_host"]}</div></div>
            <div class="info-card"><div class="label">IP</div><div class="value">{v["target_ip"]}</div></div>
            <div class="info-card"><div class="label">Puerto</div><div class="value">{v["target_port"]}</div></div>
            <div class="info-card"><div class="label">HTTPS</div><div class="value">{"✅ Sí" if v["is_https"] else "❌ No"}</div></div>
            <div class="info-card"><div class="label">WAF</div><div class="value">{v["waf_detected"] or "No detectado"}</div></div>
        </div>
    </div>

    <!-- ── 2. NIVEL DE RIESGO ── -->
    <div class="section" id="riesgo">
        <h2 class="section-title">⚠️ 2. Nivel de Riesgo General</h2>
        <div class="risk-badge">
            {v["risk_level"]}
        </div>
    </div>

    <!-- ── 3. RESUMEN ── -->
    <div class="section" id="resumen">
        <h2 class="section-title">📊 3. Resumen de Hallazgos</h2>
        {summary_bars}
        <p style="margin-top:14px;font-weight:bold;color:var(--dim)">
            Total: <span style="color:var(--text)">{v["total_findings"]} hallazgos</span>
        </p>
    </div>

    <!-- ── 4. HALLAZGOS ── -->
    <div class="section" id="hallazgos">
        <h2 class="section-title">🔍 4. Detalle de Hallazgos</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>#</th><th>Severidad</th><th>Herramienta</th><th>Fase</th>
                        <th>Título</th><th>Descripción</th><th>Evidencia</th><th>Recomendación</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows if findings_rows else '<tr><td colspan="8" style="text-align:center;color:var(--dim)">No se encontraron hallazgos</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <!-- ── 5. PUERTOS ── -->
    <div class="section" id="puertos">
        <h2 class="section-title">🌐 5. Puertos y Servicios</h2>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Puerto</th><th>Protocolo</th><th>Servicio</th><th>Versión</th></tr></thead>
                <tbody>
                    {ports_rows if ports_rows else '<tr><td colspan="4" style="text-align:center;color:var(--dim)">No se detectaron puertos abiertos</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <!-- ── 6. TECNOLOGÍAS ── -->
    <div class="section" id="tecnologias">
        <h2 class="section-title">🧩 6. Tecnologías Detectadas</h2>
        <div style="padding:10px 0">{tech_tags}</div>
    </div>

    <!-- ── 7. CABECERAS HTTP ── -->
    <div class="section" id="cabeceras">
        <h2 class="section-title">📡 7. Cabeceras HTTP de Seguridad</h2>
        <div style="margin-bottom:16px">
            <strong style="color:#2ecc71">✅ Presentes:</strong><br>
            <div style="margin:8px 0">{sec_present_tags}</div>
        </div>
        <div style="margin-bottom:16px">
            <strong style="color:#e74c3c">❌ Ausentes:</strong><br>
            <div style="margin:8px 0">{sec_missing_tags}</div>
        </div>
        <details>
            <summary style="cursor:pointer;color:var(--accent);margin-bottom:10px">Ver todas las cabeceras HTTP recibidas ({len(v["http_headers"])})</summary>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Cabecera</th><th>Valor</th></tr></thead>
                    <tbody>{headers_rows}</tbody>
                </table>
            </div>
        </details>
    </div>

    <!-- ── 8. DIRECTORIOS ── -->
    <div class="section" id="directorios">
        <h2 class="section-title">📁 8. Directorios Descubiertos ({len(v["directories_found"])})</h2>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Código</th><th>URL</th><th>Tamaño</th></tr></thead>
                <tbody>
                    {dirs_rows if dirs_rows else '<tr><td colspan="3" style="text-align:center;color:var(--dim)">No se descubrieron directorios</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <!-- ── 9. EVASIÓN ── -->
    <div class="section" id="evasion">
        <h2 class="section-title">🎭 9. Resultados de Pruebas de Evasión</h2>
        <div class="info-grid">
            <div class="info-card">
                <div class="label">Bypass WAF por cabeceras</div>
                <div class="value mono" style="font-size:0.9em">{bypass_list}</div>
            </div>
            <div class="info-card">
                <div class="label">Vectores LFI detectados</div>
                <div class="value mono" style="font-size:0.9em">{lfi_list}</div>
            </div>
            <div class="info-card">
                <div class="label">XSS Reflejados detectados</div>
                <div class="value mono" style="font-size:0.9em">{xss_list}</div>
            </div>
            <div class="info-card">
                <div class="label">Codificación URL probada</div>
                <div class="value">{"✅ Sí" if v["evasion_results"]["encoding_tested"] else "No"}</div>
            </div>
        </div>
    </div>

    <!-- ── 10. RECOPILACIÓN ── -->
    <div class="section" id="metadatos">
        <h2 class="section-title">📥 10. Recopilación de Información</h2>
        <div class="info-grid">
            <div class="info-card">
                <div class="label">Emails encontrados</div>
                <div class="value mono" style="font-size:0.85em">{emails_list}</div>
            </div>
            <div class="info-card">
                <div class="label">Rutas restringidas (robots.txt)</div>
                <div class="value mono" style="font-size:0.85em">{robots_list}</div>
            </div>
        </div>
        <div style="margin-top:16px">
            <strong>Comentarios HTML sensibles:</strong>
            {comments_list}
        </div>
    </div>

    <!-- ── 11. WHOIS ── -->
    <div class="section" id="whois">
        <h2 class="section-title">📰 11. Información WHOIS</h2>
        <div class="whois-box">{whois_display}</div>
    </div>

    <!-- ── PIE DE PÁGINA ── -->
    <div class="footer">
        <p>🛡️ WebAudit Pro v2.0 — Informe generado automáticamente el {v["scan_date"]}</p>
        <p style="margin-top:8px">
            ⚠️ Este informe es <strong>confidencial</strong>. Solo debe ser compartido con personal autorizado.
        </p>
        <p style="margin-top:8px;color:#555">
            Este análisis se realizó con fines de auditoría de seguridad bajo autorización expresa.
        </p>
    </div>

</div>
</body>
</html>"""

    # ─────────────────────────────────────────────────────────────────
    # Ofrecimiento de BurpSuite
    # ─────────────────────────────────────────────────────────────────

    def offer_burpsuite(self):
        """Ofrece lanzar Burp Suite si está disponible."""
        if not self.tools_available.get("burpsuite", False):
            return
        self.console.print()
        try:
            if Confirm.ask(
                "[cyan]Burp Suite está disponible. ¿Deseas lanzarlo para "
                "pruebas manuales adicionales?[/]"
            ):
                subprocess.Popen(
                    ["burpsuite"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.console.print("[green]Burp Suite lanzado en segundo plano.[/]")
        except Exception as exc:
            self.console.print(f"  [yellow]⚠  No se pudo lanzar Burp Suite: {exc}[/]")

    # ─────────────────────────────────────────────────────────────────
    # Orquestador principal
    # ─────────────────────────────────────────────────────────────────

    def run(self):
        """Punto de entrada principal de la auditoría."""
        try:
            self.show_banner()
            self.show_disclaimer()
            self.get_target()
            self.check_root()
            self.check_tools()
            self.setup_workdir()
            self.start_time = datetime.now()

            self.phase_recon()       # Fase 1: Reconocimiento
            self.phase_discovery()  # Fase 2: Descubrimiento
            self.phase_evasion()    # Fase 3: Evasión y bypass
            self.phase_vulnscan()   # Fase 4: Escaneo de vulnerabilidades
            self.phase_collection() # Fase 5: Recopilación de información
            self.phase_exploit()    # Fase 6: Explotación
            self.generate_report()  # Fase 7: Generación de informe
            self.offer_burpsuite()

            duration     = datetime.now() - self.start_time
            duration_str = str(duration).split(".")[0]
            self.console.print()
            self.console.print(
                Panel(
                    f"[bold green]✅ Auditoría completada en {duration_str}[/]\n"
                    f"[dim]Directorio de trabajo: {self.workdir}[/]",
                    border_style="green",
                )
            )
        except KeyboardInterrupt:
            self.console.print("\n[bold red]⚠  Auditoría cancelada por el usuario.[/]")
            sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Punto de entrada
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Suprimir advertencias de SSL no verificado si requests está disponible
    if REQUESTS_AVAILABLE:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    auditor = WebAuditPro()
    auditor.run()
