"""
AIRA Direct Agent — boucle agentique Python qui utilise tous les outils.

Remplace le LangFlow Agent (non fiable avec Ollama) par un pipeline déterministe :
  Level 1 : static strings + imports
  Level 2 : Ghidra decompilation (si disponible)
  Level 3 : angr symbolic execution (si disponible)
  Final    : Ollama interprète les résultats et donne une réponse
"""
from __future__ import annotations

from pathlib import Path

import requests

from aira.ghidra.client import GhidraClient, cascade_mcp_context
from aira.config import SYMEXEC_URL, GHIDRA_SERVER_URL

_OLLAMA_CHAT_URL = "http://127.0.0.1:11434/api/chat"

_SYSTEM = """\
You are AIRA, an expert reverse engineering assistant.
You receive binary analysis results (static strings, imports, decompiled code, symbolic execution).
Your task: find the password/flag from the evidence.

Rules:
- If a password or flag is visible in the data, state it clearly: PASSWORD: <value>
- Only report a password if it appears in the analysis data
- Never invent or guess a password
- If the password was NOT found, explain which tool would be needed (Ghidra / angr)
- Be concise and direct
"""


def _call_ollama(prompt: str, model: str, ollama_url: str) -> str:
    try:
        resp = requests.post(
            ollama_url,
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": _SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=300,
        )
        if resp.ok:
            return resp.json()["message"]["content"]
        return f"Ollama error {resp.status_code}: {resp.text[:300]}"
    except Exception as exc:
        return f"Cannot reach Ollama ({ollama_url}): {exc}"


def solve(
    binary_path: str,
    question: str = "Find the password in this binary.",
    model: str = "qwen2.5-coder:latest",
    ollama_url: str = _OLLAMA_CHAT_URL,
    ghidra_url: str = str(GHIDRA_SERVER_URL),
    symexec_url: str = str(SYMEXEC_URL),
) -> dict:
    """
    Run the full analysis cascade then ask Ollama to interpret the results.

    Returns a dict:
      {
        "model": str,
        "output_text": str,   # final LLM answer
        "context": str,       # raw cascade context (for debug)
        "levels_used": list,  # which levels ran
      }
    """
    path = Path(binary_path)
    if not path.exists():
        return {
            "model": f"aira:{model}",
            "output_text": f"Error: binary not found: {binary_path}",
            "context": "",
            "levels_used": [],
        }

    # ── Run full cascade ──────────────────────────────────────────────────────
    ghidra = GhidraClient(base_url=ghidra_url)
    context = cascade_mcp_context(
        binary_path,
        question=question,
        ghidra_client=ghidra if ghidra.is_available() else None,
        symexec_url=symexec_url,
    )

    levels_used = []
    if "[Level 1" in context:
        levels_used.append("static")
    if "[Level 2" in context:
        levels_used.append("ghidra")
    if "[Level 3" in context:
        levels_used.append("angr")

    if not context:
        return {
            "model": f"aira:{model}",
            "output_text": "Error: the analysis produced no results.",
            "context": "",
            "levels_used": [],
        }

    # ── Ask Ollama to interpret ───────────────────────────────────────────────
    prompt = (
        f"## Binary analysis results\n\n{context}\n\n"
        f"## Question\n\n{question}\n\n"
        "Based ONLY on the analysis data above, answer the question.\n"
        "If you find a password, state it as: PASSWORD: <value>"
    )
    answer = _call_ollama(prompt, model=model, ollama_url=ollama_url)

    return {
        "model": f"aira:{model}",
        "output_text": answer,
        "context": context,
        "levels_used": levels_used,
    }
