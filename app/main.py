import asyncio
import os
import re
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .backend.config import get_settings
from .backend.logger import get_logger
from .backend.schemas import (
    ChatRequest,
    ChatResponse,
    HistoryResponse,
    Message,
    StaticAnalyzeRequest,
    StaticAnalyzeResponse,
)
from .backend.services import openai_client, langflow_client, azure_openai_client
from .backend import analysis as analysis_svc


logger = get_logger("server")
settings = get_settings()

# ── Session store en mémoire ───────────────────────────────────────────────
# Structure : { session_id: { "messages": [...], "binary_path": str | None } }
_sessions: Dict[str, dict] = {}


def _get_session(session_id: str) -> dict:
    if session_id not in _sessions:
        _sessions[session_id] = {"messages": [], "binary_path": None, "deep_analysis": None}
    return _sessions[session_id]


# Rate limiter configuration
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="AIRA - AI-Assisted Reversing Analyser", version="0.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS configuration - restrict to localhost in development
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# Static web UI
FRONTEND_DIR = Path(__file__).parent / "frontend"
FRONTEND_DIR.mkdir(parents=True, exist_ok=True)


UPLOAD_DIR = (Path(__file__).parent.parent / "data" / "uploads").resolve()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Allowed file extensions for binary analysis
ALLOWED_EXTENSIONS = {".exe", ".dll", ".so", ".elf", ".bin", ".o", ".dylib", ".war", ".jar", ".ear"}

# Filename sanitization pattern
SAFE_FILENAME_PATTERN = re.compile(r"^[\w\-. ]+$")


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal attacks."""
    # Remove path components
    filename = Path(filename).name
    # Check for safe characters
    if not SAFE_FILENAME_PATTERN.match(filename):
        # Replace unsafe characters
        filename = re.sub(r"[^\w\-. ]", "_", filename)
    # Prevent hidden files
    if filename.startswith("."):
        filename = "_" + filename[1:]
    return filename


def validate_file_extension(filename: str) -> bool:
    """Check if the file extension is allowed for binary analysis."""
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


@app.get("/api/health")
@limiter.limit("60/minute")
def health(request: Request):
    return {"status": "ok", "provider": settings.default_provider}


@app.get("/api/providers")
@limiter.limit("60/minute")
def list_providers(request: Request):
    return {
        "default": settings.default_provider,
        "supported": ["openai", "langflow", "azure"],
    }


@app.post("/api/chat", response_model=ChatResponse)
@limiter.limit("10/minute")
async def chat(request: Request, req: ChatRequest):
    provider = req.provider or settings.default_provider

    # ── Résolution session_id ──────────────────────────────────────────────
    session_id = req.session_id or str(uuid.uuid4())
    session = _get_session(session_id)

    # Mise à jour du chemin binaire si fourni
    if req.binary_path:
        session["binary_path"] = req.binary_path

    # Construction de la liste de messages à envoyer à l'IA
    if req.message is not None:
        # Mode session : on ajoute juste le nouveau message à l'historique
        session["messages"].append({"role": "user", "content": req.message})
        messages_for_ai = [Message(role=m["role"], content=m["content"]) for m in session["messages"]]
    elif req.messages:
        # Mode legacy : liste complète envoyée par le client
        messages_for_ai = req.messages
        # On synchronise l'historique session avec ce que le client envoie
        session["messages"] = [{"role": m.role, "content": m.content} for m in req.messages]
    else:
        raise HTTPException(status_code=400, detail="Fournir 'message' (mode session) ou 'messages' (mode legacy).")

    # Injecter le contexte binaire + deep analysis comme messages système
    binary_path = session.get("binary_path") or ""
    system_parts: list[str] = []
    if binary_path:
        system_parts.append(f"Fichier binaire analysé : {binary_path}")
    if session.get("deep_analysis"):
        try:
            from aira.deep_analysis import format_for_llm
            deep_ctx = format_for_llm(session["deep_analysis"])
            if deep_ctx:
                system_parts.append(f"[Analyse approfondie]\n{deep_ctx}")
        except Exception:
            pass
    if session.get("war_analysis"):
        try:
            from aira.analyzers.war_analyzer import format_war_for_llm
            war_ctx = format_war_for_llm(session["war_analysis"])
            if war_ctx:
                system_parts.append(f"[Analyse WAR]\n{war_ctx}")
        except Exception:
            pass
    if system_parts:
        sys_msg = Message(role="system", content="\n\n".join(system_parts))
        messages_for_ai = [sys_msg] + [m for m in messages_for_ai if m.role != "system"]

    try:
        def _run_sync():
            if provider == "openai":
                return openai_client.chat_completion(
                    messages=messages_for_ai,
                    model=req.model,
                    temperature=req.temperature or 0.2,
                    top_p=req.top_p or 1.0,
                )
            elif provider == "langflow":
                return langflow_client.run_flow(
                    messages=messages_for_ai,
                    flow_id=req.langflow_flow_id,
                    temperature=req.temperature or 0.2,
                    top_p=req.top_p or 1.0,
                )
            elif provider == "azure":
                return azure_openai_client.chat_completion(
                    messages=messages_for_ai,
                    model=req.model,
                    temperature=req.temperature or 0.2,
                    top_p=req.top_p or 1.0,
                )
            elif provider == "aira":
                from aira.agent import solve as aira_solve
                question = next(
                    (m.content for m in reversed(messages_for_ai) if m.role == "user"), ""
                )
                if not binary_path:
                    raise HTTPException(
                        status_code=400,
                        detail="AIRA provider requires a binary (upload a file first).",
                    )
                return aira_solve(
                    binary_path=binary_path,
                    question=question,
                    model=settings.ollama_model,
                    ollama_url=f"{settings.ollama_base_url}/api/chat",
                    ghidra_url=settings.ghidra_server_url,
                    symexec_url=settings.symexec_url,
                )
            elif provider == "claudecode":
                import subprocess
                # Construire le prompt avec tout l'historique
                #lines = ["Tu es un assistant en rétro-ingénierie de binaires."]
                lines = ["""Tu es AIRA, un assistant expert en reverse engineering. Tu analyses des binaires pour trouver des mots de passe, flags ou solutions.

                  OUTILS DISPONIBLES (utilise uniquement ceux-ci) :
                  - set_binary(path)
                  - full_analysis(path)
                  - extract_strings(min_len, path)
                  - static_info(path)
                  - ghidra_status()
                  - ghidra_find_entrypoint()
                  - ghidra_list_functions()
                  - ghidra_decompile(function_name)
                  - ghidra_decompile_at(address)
                  - ghidra_list_strings()
                  - ghidra_list_imports()
                  - symbolic_solve(target_address, avoid_addresses, stdin_len, input_mode)
                  - symbolic_auto_solve(stdin_len)

                  FLUX DE TRAVAIL OBLIGATOIRE — exécute chaque étape sans t'arrêter :
                  1. Appeler full_analysis(path=<chemin fourni par l'utilisateur dans son message>)
                  2. Appeler ghidra_find_entrypoint() — trouve et décompile le vrai main()
                  3. Si le entrypoint appelle d'autres fonctions suspectes → ghidra_decompile(name) sur chacune
                  4. Si toujours pas de mot de passe → symbolic_auto_solve()

                  RÈGLES STRICTES :
                  - Le chemin du binaire est donné par l'utilisateur dans son message. Utilise-le DIRECTEMENT, ne cherche pas [Binary].
                  - Ne jamais s'arrêter pour "recommander" une étape. Exécuter immédiatement.
                  - Ne rendre un résultat final QUE si : mot de passe trouvé, OU toutes les étapes 1-4 ont été tentées.
                  - Ne jamais inventer un mot de passe sans preuve issue d'un outil.
                  - Pour les binaires MinGW/GCC : "main" n'existe pas — utiliser ghidra_find_entrypoint().
                  - Ne pas se faire avoir par des decoy toujours analyser une deuxième fois 

                Si ghidra_find_entrypoint() retourne "Ghidra not available",
                    ARRÊTE-TOI et dis à l'utilisateur : "Lance Ghidra avec le plugin HTTP
                    (port 8080) et charge le binaire, puis relance l'analyse."
                    Ne continue pas avec symbolic_auto_solve dans ce cas.
                """]
                if binary_path:
                    lines.append(f"Fichier analysé : {binary_path}")
                lines.append("")
                for m in messages_for_ai:
                    if m.role == "system":
                        continue
                    prefix = "Utilisateur" if m.role == "user" else "Assistant"
                    lines.append(f"{prefix} : {m.content}")
                prompt = "\n".join(lines)
                claude_bin = os.getenv("CLAUDE_BIN", "claude")
                mcp_config = os.getenv(
                    "CLAUDE_MCP_CONFIG",
                    str(Path(__file__).parent.parent / "claude_mcp_config.json"),
                )
                aira_tools = [
                    "mcp__aira__set_binary",
                    "mcp__aira__get_binary",
                    "mcp__aira__static_info",
                    "mcp__aira__extract_strings",
                    "mcp__aira__ghidra_status",
                    "mcp__aira__ghidra_list_functions",
                    "mcp__aira__ghidra_find_entrypoint",
                    "mcp__aira__ghidra_decompile",
                    "mcp__aira__ghidra_decompile_at",
                    "mcp__aira__ghidra_list_strings",
                    "mcp__aira__ghidra_list_imports",
                    "mcp__aira__symbolic_solve",
                    "mcp__aira__symbolic_auto_solve",
                    "mcp__aira__full_analysis",
                    "mcp__aira__analyze_war_file",
                    "mcp__aira__war_detailed_analysis"
                ]
                cmd = [
                    claude_bin, "-p", prompt,
                    "--mcp-config", mcp_config,
                    "--allowedTools", ",".join(aira_tools),
                ]
                proc = subprocess.run(
                    cmd,
                    capture_output=True, text=True, timeout=None,
                    encoding="utf-8", errors="replace",
                )
                if proc.returncode != 0:
                    raise RuntimeError(proc.stderr or "claude CLI error")
                return {"output_text": proc.stdout.strip()}
            else:
                raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

        result = await asyncio.to_thread(_run_sync)

        # Sauvegarder la réponse dans l'historique session
        output_text = result.get("output_text", "")
        session["messages"].append({"role": "assistant", "content": output_text})

        return ChatResponse(provider=provider, session_id=session_id, **result)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("chat error")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/chat/history/{session_id}", response_model=HistoryResponse)
@limiter.limit("60/minute")
def get_history(request: Request, session_id: str):
    """Retourne l'historique d'une session de conversation."""
    session = _sessions.get(session_id)
    if not session:
        return HistoryResponse(session_id=session_id, messages=[], binary_path=None)
    msgs = [Message(role=m["role"], content=m["content"]) for m in session["messages"]]
    return HistoryResponse(session_id=session_id, messages=msgs, binary_path=session.get("binary_path"))


@app.delete("/api/chat/history/{session_id}")
@limiter.limit("30/minute")
def delete_history(request: Request, session_id: str):
    """Efface l'historique d'une session."""
    _sessions.pop(session_id, None)
    return {"status": "cleared", "session_id": session_id}


@app.post("/api/upload")
@limiter.limit("5/minute")
async def upload(request: Request, file: UploadFile = File(...), note: Optional[str] = Form(None)):
    # Validate file size
    content = await file.read()
    if len(content) > settings.max_upload_size:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {settings.max_upload_size // (1024*1024)} MB"
        )

    # Sanitize filename
    safe_filename = sanitize_filename(file.filename or "unknown")
    dest = UPLOAD_DIR / safe_filename

    # Avoid overwriting existing files
    if dest.exists():
        base = dest.stem
        ext = dest.suffix
        counter = 1
        while dest.exists():
            dest = UPLOAD_DIR / f"{base}_{counter}{ext}"
            counter += 1

    dest.write_bytes(content)
    return {
        "filename": dest.name,
        "bytes": len(content),
        "note": note,
        "path": str(dest),
    }


@app.get("/api/uploads/{filename}")
@limiter.limit("30/minute")
def get_upload(request: Request, filename: str):
    # Sanitize the requested filename
    safe_filename = sanitize_filename(filename)
    path = UPLOAD_DIR / safe_filename

    # Ensure the resolved path is within UPLOAD_DIR (prevent traversal)
    try:
        path.resolve().relative_to(UPLOAD_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied")

    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path)


@app.post("/api/analyze/static-info", response_model=StaticAnalyzeResponse)
@limiter.limit("20/minute")
def analyze_static(request: Request, req: StaticAnalyzeRequest):
    path = Path(req.path)

    # Security: Validate path is within allowed directories
    try:
        resolved = path.resolve()
        # Allow paths in UPLOAD_DIR or current working directory
        allowed_bases = [UPLOAD_DIR.resolve(), Path.cwd().resolve()]
        is_allowed = any(
            str(resolved).startswith(str(base)) for base in allowed_bases
        )
        if not is_allowed:
            logger.warning(f"Path traversal attempt blocked: {req.path}")
            raise HTTPException(status_code=403, detail="Access denied: path outside allowed directories")
    except (ValueError, OSError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid path: {req.path}")

    if not path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {req.path}")
    try:
        info = analysis_svc.static_info(str(path))
        matches = analysis_svc.yara_antidebug(str(path)) if req.yara else None
        return StaticAnalyzeResponse(path=str(path), info=info, yara_matches=matches)
    except Exception as e:
        logger.exception("static analyze error")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/api/upload/analyze", response_model=StaticAnalyzeResponse)
@limiter.limit("5/minute")
async def upload_and_analyze(request: Request, file: UploadFile = File(...), yara: Optional[bool] = Form(False)):
    # Validate file size
    content = await file.read()
    if len(content) > settings.max_upload_size:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {settings.max_upload_size // (1024*1024)} MB"
        )

    # Sanitize filename
    safe_filename = sanitize_filename(file.filename or "unknown")

    # Warn if extension is not typical for binary analysis
    if not validate_file_extension(safe_filename):
        logger.warning(f"Non-standard file extension for binary analysis: {safe_filename}")

    dest = UPLOAD_DIR / safe_filename
    dest.write_bytes(content)

    try:
        info = analysis_svc.static_info(str(dest))
        matches = analysis_svc.yara_antidebug(str(dest)) if yara else None
        return StaticAnalyzeResponse(path=str(dest), info=info, yara_matches=matches)
    except Exception as e:
        logger.exception("upload+analyze error")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/api/analyze/deep")
@limiter.limit("5/minute")
async def deep_analyze(
    request: Request,
    file: UploadFile = File(...),
    session_id: Optional[str] = Form(None),
):
    """
    Upload + deep analysis complète (entropie, hashes, packer, API behavior,
    strings classifiées, YARA multi-règles, désassemblage EP optionnel).
    Si session_id fourni, stocke les résultats dans la session pour le chat.
    """
    content = await file.read()
    if len(content) > settings.max_upload_size:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum: {settings.max_upload_size // (1024*1024)} MB",
        )

    safe_filename = sanitize_filename(file.filename or "unknown")
    dest = UPLOAD_DIR / safe_filename
    if dest.exists():
        base, ext = dest.stem, dest.suffix
        counter = 1
        while dest.exists():
            dest = UPLOAD_DIR / f"{base}_{counter}{ext}"
            counter += 1
    dest.write_bytes(content)

    try:
        from aira.deep_analysis import run_deep_analysis
        result = await asyncio.to_thread(run_deep_analysis, str(dest))
    except Exception as e:
        logger.exception("deep analyze error")
        raise HTTPException(status_code=500, detail=str(e)) from e

    # Stocker dans la session si session_id fourni
    if session_id:
        sess = _get_session(session_id)
        sess["binary_path"]   = str(dest)
        sess["deep_analysis"] = result

    result["path"] = str(dest)
    return result


@app.post("/api/analyze/war")
@limiter.limit("5/minute")
async def analyze_war_endpoint(
    request: Request,
    file: UploadFile = File(...),
    session_id: Optional[str] = Form(None),
):
    """
    Upload + analyse complète d'un fichier WAR (Java Web Application Archive).
    Détecte : webshells, bibliothèques vulnérables, APIs dangereuses,
    secrets hardcodés, misconfigurations, et plus.
    """
    content = await file.read()
    if len(content) > settings.max_upload_size:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum: {settings.max_upload_size // (1024*1024)} MB",
        )

    safe_filename = sanitize_filename(file.filename or "unknown.war")
    ext = Path(safe_filename).suffix.lower()
    if ext not in (".war", ".jar", ".ear", ".zip"):
        raise HTTPException(status_code=400, detail=f"Expected .war/.jar/.ear file, got: {ext}")

    dest = UPLOAD_DIR / safe_filename
    if dest.exists():
        base, suffix = dest.stem, dest.suffix
        counter = 1
        while dest.exists():
            dest = UPLOAD_DIR / f"{base}_{counter}{suffix}"
            counter += 1
    dest.write_bytes(content)

    try:
        from aira.analyzers.war_analyzer import analyze_war
        result = await asyncio.to_thread(analyze_war, str(dest))
    except Exception as e:
        logger.exception("WAR analyze error")
        raise HTTPException(status_code=500, detail=str(e)) from e

    # YARA scan additionnel
    yara_matches = []
    try:
        from aira.static_detection import scan_with_yara
        yara_rules = Path(__file__).parent.parent / "signatures" / "java_war.yar"
        if yara_rules.exists():
            yara_matches = await asyncio.to_thread(scan_with_yara, str(dest), str(yara_rules))
    except Exception as e:
        logger.warning(f"WAR YARA scan failed: {e}")

    if yara_matches:
        result["yara_java"] = yara_matches

    # Stocker dans la session si session_id fourni
    if session_id:
        sess = _get_session(session_id)
        sess["binary_path"] = str(dest)
        sess["war_analysis"] = result

    result["path"] = str(dest)
    return result


app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


def run():
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=os.getenv("RELOAD", "1") == "1",
        timeout_keep_alive=300,   # Maintient la connexion ouverte 5 min
        h11_max_incomplete_event_size=16 * 1024 * 1024,
    )


if __name__ == "__main__":
    run()
