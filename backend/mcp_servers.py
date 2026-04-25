"""
Configuraciones del servidor MCP y preparación de herramientas de análisis de seguridad.
"""

import os
import subprocess
from typing import Dict, Any
from agents.mcp import MCPServerStdio, create_static_tool_filter

import sys

def get_semgrep_server_params() -> Dict[str, Any]:
    semgrep_app_token = os.getenv("SEMGREP_APP_TOKEN")
    
    # Ruta al python del venv actual
    python_path = sys.executable
    
    env = {
        "SEMGREP_APP_TOKEN": semgrep_app_token or "",
        "PYTHONUNBUFFERED": "1",
        "PATH": r"C:\Users\JEXPO\.local\bin" + ";" + os.environ.get("PATH", ""),
        "USERPROFILE": os.environ.get("USERPROFILE", ""),
        "APPDATA": os.environ.get("APPDATA", ""),
        "LOCALAPPDATA": os.environ.get("LOCALAPPDATA", ""),
    }
    
    return {
        "command": python_path,
        "args": ["-m", "semgrep_mcp"],
        "env": env,
    }

def create_semgrep_server() -> MCPServerStdio:
    """Crea y configura la instancia del servidor MCP de Semgrep."""
    params = get_semgrep_server_params()
    return MCPServerStdio(
        params=params,
        client_session_timeout_seconds=120,
        tool_filter=create_static_tool_filter(allowed_tool_names=["semgrep_scan"]),
    )

