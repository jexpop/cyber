import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import List
from dotenv import load_dotenv
from agents import Agent, Runner, trace

from context import SECURITY_RESEARCHER_INSTRUCTIONS, get_analysis_prompt, enhance_summary
from mcp_servers import create_semgrep_server

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


load_dotenv()
print("OPENAI_API_KEY:", bool(os.getenv("OPENAI_API_KEY")))
print("Directorio actual:", os.getcwd())

app = FastAPI(title="API de Analizador de Ciberseguridad")

# Configurar CORS para desarrollo y producción
cors_origins = [
    "http://localhost:3000",    # Desarrollo local
    "http://frontend:3000",     # Desarrollo con Docker
]

# En producción, permitir solicitudes del mismo origen (archivos estáticos servidos desde el mismo dominio)
if os.getenv("ENVIRONMENT") == "production":
    cors_origins.append("*")  # Permitir todos los orígenes en producción ya que servimos el frontend desde el mismo dominio

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    code: str


class SecurityIssue(BaseModel):
    title: str = Field(description="Título breve de la vulnerabilidad de seguridad")
    description: str = Field(
        description="Descripción detallada del problema de seguridad y su posible impacto"
    )
    code: str = Field(
        description="El fragmento específico de código vulnerable que muestra el problema"
    )
    fix: str = Field(description="Reparación o estrategia de mitigación recomendada para el código")
    cvss_score: float = Field(description="Puntaje CVSS de 0.0 a 10.0 que indica la gravedad")
    severity: str = Field(description="Nivel de severidad: crítico, alto, medio o bajo")


class SecurityReport(BaseModel):
    summary: str = Field(description="Resumen ejecutivo del análisis de seguridad")
    issues: List[SecurityIssue] = Field(description="Lista de vulnerabilidades de seguridad identificadas")


def validate_request(request: AnalyzeRequest) -> None:
    """Valida la solicitud de análisis."""
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="No se proporcionó código para analizar")


def check_api_keys() -> None:
    """Verifica que las claves de API requeridas estén configuradas."""
    if not os.getenv("OPENAI_API_KEY"):
        raise HTTPException(status_code=500, detail="No se configuró la clave de API de OpenAI")


def create_security_agent(semgrep_server) -> Agent:
    """Crea y configura el agente de análisis de seguridad."""
    return Agent(
        name="Security Researcher",
        instructions=SECURITY_RESEARCHER_INSTRUCTIONS,
        model="gpt-4.1-mini",
        mcp_servers=[semgrep_server],
        output_type=SecurityReport,
    )


async def run_security_analysis(code: str) -> SecurityReport:
    """Ejecuta el flujo de trabajo de análisis de seguridad."""
    with trace("Security Researcher"):
        async with create_semgrep_server() as semgrep:
            agent = create_security_agent(semgrep)
            result = await Runner.run(agent, input=get_analysis_prompt(code))
            return result.final_output_as(SecurityReport)


def format_analysis_response(code: str, report: SecurityReport) -> SecurityReport:
    """Da formato a la respuesta final de análisis."""
    enhanced_summary = enhance_summary(len(code), report.summary)
    return SecurityReport(summary=enhanced_summary, issues=report.issues)


@app.post("/api/analyze", response_model=SecurityReport)
async def analyze_code(request: AnalyzeRequest) -> SecurityReport:
    """
    Analiza código Python en busca de vulnerabilidades de seguridad usando OpenAI Agents y Semgrep.

    Este endpoint combina análisis estático mediante Semgrep con análisis de seguridad potenciado por IA
    para proporcionar detección integral de vulnerabilidades y orientación para su remediación.
    """
    validate_request(request)
    check_api_keys()

    try:
        report = await run_security_analysis(request.code)
        return format_analysis_response(request.code, report)
    except Exception as e:
        logger.error(f"Error: {type(e).__name__}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)}")


@app.get("/health")
async def health():
    """Endpoint de verificación de estado (health check)."""
    return {"message": "API de Analizador de Ciberseguridad"}

@app.get("/network-test")
async def network_test():
    """Prueba la conectividad de red con la API de Semgrep."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get("https://semgrep.dev/api/v1/")
            return {
                "semgrep_api_reachable": True,
                "status_code": response.status_code,
                "response_size": len(response.content)
            }
    except Exception as e:
        return {
            "semgrep_api_reachable": False,
            "error": str(e)
        }

@app.get("/semgrep-test")
async def semgrep_test():
    """Prueba si el CLI de semgrep puede ser instalado y ejecutado."""
    import subprocess
    import tempfile
    import os
    
    try:
        # Prueba si podemos instalar semgrep usando pip
        result = subprocess.run(
            ["pip", "install", "semgrep"], 
            capture_output=True, 
            text=True, 
            timeout=60
        )
        
        if result.returncode != 0:
            return {
                "semgrep_install": False,
                "error": f"Instalación fallida: {result.stderr}"
            }
        
        # Prueba si semgrep --version funciona
        version_result = subprocess.run(
            ["semgrep", "--version"], 
            capture_output=True, 
            text=True, 
            timeout=30
        )
        
        return {
            "semgrep_install": True,
            "version_check": version_result.returncode == 0,
            "version_output": version_result.stdout,
            "version_error": version_result.stderr
        }
        
    except subprocess.TimeoutExpired:
        return {
            "semgrep_install": False,
            "error": "Tiempo de espera superado durante la instalación o verificación de semgrep"
        }
    except Exception as e:
        return {
            "semgrep_install": False,
            "error": str(e)
        }

# Montar archivos estáticos para el frontend
if os.path.exists("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
