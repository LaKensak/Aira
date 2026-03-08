"""
AIRA Unified MCP Server — exposes all analysis tools to LangFlow Agent.

Launch:  python -m aira.mcp_server --transport sse --port 8082
LangFlow: connect MCP component to http://127.0.0.1:8082/sse
"""
import argparse
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("aira-tools")

# ── State persistence ─────────────────────────────────────────────────────────
# _binary persists across requests AND server restarts via a small state file.
_STATE_FILE = Path(__file__).resolve().parent.parent / "data" / ".mcp_state.json"

def _load_state() -> str:
    try:
        if _STATE_FILE.exists():
            data = json.loads(_STATE_FILE.read_text())
            p = Path(data.get("binary", ""))
            if p.exists():
                return str(p)
    except Exception:
        pass
    return ""

def _save_state(binary: str) -> None:
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps({"binary": binary}))
    except Exception:
        pass

_binary: str = _load_state()


# ── Binary selection ──────────────────────────────────────────────────────────

@mcp.tool()
def set_binary(path: str) -> str:
    """
    Set the binary file to analyze for this session.
    Must be called before using analysis tools when the binary path is known.
    The path is persisted on disk so it survives server restarts.
    """
    global _binary
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"
    _binary = str(p.resolve())
    _save_state(_binary)
    return f"Binary set: {_binary}"


@mcp.tool()
def get_binary() -> str:
    """Return the currently selected binary path, or an error if none is set."""
    global _binary
    if not _binary:
        _binary = _load_state()
    if _binary:
        return f"Current binary: {_binary}"
    return "No binary set. Use set_binary(path) first."


def _require_binary() -> str | None:
    """Return error string if no binary is set, else None."""
    global _binary
    if not _binary:
        _binary = _load_state()
    return None if _binary else "Error: no binary set. Call set_binary(path) first."


# ── Level 1 — Static analysis ─────────────────────────────────────────────────

@mcp.tool()
def static_info(path: str = "") -> str:
    """
    Return basic static information about the binary:
    format, architecture, imagebase, entrypoint, section list, import symbols.
    Optional: pass path to set the binary at the same time (calls set_binary internally).
    """
    global _binary
    if path:
        p = Path(path)
        if not p.exists():
            return f"Error: file not found: {path}"
        _binary = str(p.resolve())
        _save_state(_binary)
    if err := _require_binary():
        return err
    try:
        from aira.static_analysis import get_basic_info
        info = get_basic_info(_binary)
        lines = [
            f"Format: {info.format}",
            f"Architecture: {info.architecture}",
            f"Imagebase: {info.imagebase_hex}",
            f"Entrypoint: {info.entrypoint_hex}",
            f"Sections ({len(info.sections)}): " + ", ".join(s["name"] for s in info.sections),
            f"Imports ({len(info.imports)}): " + ", ".join(
                i.get("symbol", "") for i in info.imports[:40] if i.get("symbol")
            ),
        ]
        return "\n".join(lines)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def extract_strings(min_len: int = 4, path: str = "") -> str:
    """
    Extract printable ASCII strings from the binary.
    Filters out compiler noise and sorts by relevance (password candidates first).
    Optional: pass path to set the binary at the same time.
    """
    global _binary
    if path:
        p = Path(path)
        if not p.exists():
            return f"Error: file not found: {path}"
        _binary = str(p.resolve())
        _save_state(_binary)
    if err := _require_binary():
        return err
    try:
        from aira.static_analysis import extract_strings as _ext
        from aira.ghidra.client import _filter_strings
        raw = _ext(_binary, min_len=min_len)
        filtered = _filter_strings(raw)
        return (
            f"Extracted {len(raw)} strings, {len(filtered)} after filtering:\n"
            + "\n".join(filtered[:100])
        )
    except Exception as exc:
        return f"Error: {exc}"


# ── Level 2 — Ghidra decompilation ───────────────────────────────────────────

@mcp.tool()
def ghidra_status() -> str:
    """Check whether the Ghidra HTTP plugin is reachable on port 8080."""
    from aira.ghidra.client import GhidraClient
    g = GhidraClient()
    if g.is_available():
        return "Ghidra is available. Ready for decompilation."
    return "Ghidra not available. Start Ghidra and enable the HTTP plugin (port 8080)."


_CRT_PREFIXES = (
    "__mingw", "pre_c_init", "pre_cpp_init", "__tmain", "WinMain", "mainCRT",
    "__tcf_", "__static_init", "_GLOBAL__", "d_make", "d_cv_", "d_ref_", "d_sub",
    "d_count", "d_append", "d_number", "d_compact", "d_template", "d_discrim",
    "d_source", "d_call_", "d_lookup", "d_find_", "d_print", "d_expr", "d_type",
    "d_parm", "d_bare", "d_func", "d_oper", "d_unqual", "d_name", "d_encod",
    "d_deman", "d_exprlist", "d_expres", "d_vector", "__cxa_", "__gcclibcxx",
    "_decode_", "_encode_", "_setargv", "_matherr", "__report_", "__write_",
    "_pei386", "__mingw_SEH", "__mingw_init", "_gnu_ex", "_fpreset", "__do_global",
    "__main", "__security", "__dyn_tls", "__tlreg", "mingw_one", "atexit",
    "my_lconv", "_Validate", "_FindPE", "__mingw_Get", "_GetPE", "_IsNon",
    "__mingwthr", "___w64_mingw", "_Unwind_", "FUN_", "__gnu_",
)


@mcp.tool()
def ghidra_list_functions() -> str:
    """
    List user-defined functions in the binary (CRT/MinGW runtime noise is filtered out).
    Call this to find the actual application logic functions.
    """
    from aira.ghidra.client import GhidraClient
    g = GhidraClient()
    if not g.is_available():
        return "Ghidra not available."
    funcs = g.list_functions(limit=2000)
    total = len(funcs)

    def _is_user(f: str) -> bool:
        name = f.split(" at ")[0]
        return not any(name.startswith(p) for p in _CRT_PREFIXES)

    user_funcs = [f for f in funcs if _is_user(f)]
    shown = user_funcs[:60]
    return (
        f"Total: {total} functions, {len(user_funcs)} user-defined (showing up to 60):\n"
        + "\n".join(shown)
    )


@mcp.tool()
def ghidra_find_entrypoint() -> str:
    """
    Find and decompile the real user entrypoint (main/WinMain equivalent).
    Works for MinGW/GCC/MSVC binaries where 'main' symbol may be missing.
    Returns the decompiled code of the first user-written function called at startup.
    Use this instead of ghidra_decompile('main') for crackmes and CTF binaries.
    """
    from aira.ghidra.client import GhidraClient
    g = GhidraClient()
    if not g.is_available():
        return "Ghidra not available."

    # Strategy 1: look for .text function right after the CRT startup chain
    funcs = g.list_functions(limit=2000)
    text_funcs = [f for f in funcs if f.startswith(".text at ")]
    if text_funcs:
        addr = text_funcs[0].split(" at ")[-1].strip()
        lines = g.decompile_at(f"0x{addr}")
        if lines:
            return f"User entrypoint at {addr}:\n" + "\n".join(lines)

    # Strategy 2: try common user entry names
    for name in ("main", "WinMain", "wWinMain", "wmain", "_main"):
        lines = g.decompile(name)
        if lines:
            return f"User entrypoint '{name}':\n" + "\n".join(lines)

    # Strategy 3: decompile __tmainCRTStartup and show call targets
    lines = g.decompile("__tmainCRTStartup")
    if lines:
        return "Could not isolate user entry. __tmainCRTStartup:\n" + "\n".join(lines)

    return "Could not find user entrypoint. Use ghidra_list_functions() and ghidra_decompile_at() manually."


@mcp.tool()
def ghidra_decompile(function_name: str) -> str:
    """
    Decompile a specific function by name via Ghidra.
    Use ghidra_list_functions() first to get valid function names.
    For MinGW/GCC binaries, 'main' may not exist — try ghidra_find_entrypoint() instead.
    """
    from aira.ghidra.client import GhidraClient
    g = GhidraClient()
    if not g.is_available():
        return "Ghidra not available."
    lines = g.decompile(function_name)
    if not lines:
        # For 'main', try common MinGW aliases automatically
        if function_name in ("main", "Main"):
            for alias in ("WinMainCRTStartup", "mainCRTStartup", "__tmainCRTStartup"):
                lines = g.decompile(alias)
                if lines:
                    return f"('{function_name}' not found, showing '{alias}' instead)\n" + "\n".join(lines)
        return f"No decompilation result for '{function_name}'. Use ghidra_list_functions() to find valid names."
    return "\n".join(lines)


@mcp.tool()
def ghidra_decompile_at(address: str) -> str:
    """
    Decompile the function at a specific virtual address (hex, e.g. '0x140001450').
    """
    from aira.ghidra.client import GhidraClient
    g = GhidraClient()
    if not g.is_available():
        return "Ghidra not available."
    lines = g.decompile_at(address)
    if not lines:
        return f"No decompilation result at address {address}."
    return "\n".join(lines)


@mcp.tool()
def ghidra_list_strings() -> str:
    """List strings extracted by Ghidra from the loaded binary."""
    from aira.ghidra.client import GhidraClient
    g = GhidraClient()
    if not g.is_available():
        return "Ghidra not available."
    strings = g.list_strings()
    return f"Found {len(strings)} strings:\n" + "\n".join(strings[:200])


@mcp.tool()
def ghidra_list_imports() -> str:
    """List imported symbols via Ghidra."""
    from aira.ghidra.client import GhidraClient
    g = GhidraClient()
    if not g.is_available():
        return "Ghidra not available."
    imports = g.list_imports()
    return "\n".join(imports[:100])


# ── Level 3 — angr symbolic execution ────────────────────────────────────────

@mcp.tool()
def symbolic_solve(
    target_address: str,
    avoid_addresses: str = "",
    stdin_len: int = 64,
    input_mode: str = "stdin",
) -> str:
    """
    Use angr symbolic execution to find the input that reaches target_address.

    target_address:  hex VA of the success/goal basic block (e.g. '0x140001530').
    avoid_addresses: comma-separated hex VAs of failure/exit blocks to avoid.
    stdin_len:       maximum length of stdin input to explore (default 64).
    input_mode:      'stdin' or 'argv' (default 'stdin').

    Requires the symexec service to be running:
      python -m services.symexec_service.server
    """
    if err := _require_binary():
        return err
    try:
        from aira.symexec.client import solve, SolveRequest
        avoid_list = [a.strip() for a in avoid_addresses.split(",") if a.strip()]
        req = SolveRequest(
            binary_path=_binary,
            addr_target=target_address,
            addr_avoid=avoid_list,
            stdin_len=stdin_len,
            input_mode=input_mode,
        )
        result = solve(req)
        solution = (
            result.get("solution")
            or result.get("stdin")
            or result.get("input")
            or ""
        )
        if solution:
            return f"PASSWORD FOUND: {solution!r}"
        return f"No solution found. Raw result: {result}"
    except Exception as exc:
        return f"Error (is the symexec service running?): {exc}"


@mcp.tool()
def symbolic_auto_solve(stdin_len: int = 64) -> str:
    """
    Automatically find success/failure addresses using LIEF, then call angr.
    Does not require knowing the target address in advance.
    Requires the symexec service: python -m services.symexec_service.server
    """
    if err := _require_binary():
        return err
    from aira.ghidra.client import _angr_auto_solve
    from aira.config import SYMEXEC_URL
    result = _angr_auto_solve(_binary, symexec_url=str(SYMEXEC_URL))
    return result if result else (
        "Auto-solve failed: could not locate success/failure string addresses.\n"
        "Try symbolic_solve(target_address='0x...') with a known address."
    )


# ── Level 4 — Convenience / orchestration ────────────────────────────────────

@mcp.tool()
def full_analysis(path: str) -> str:
    """
    Run a complete static analysis of a binary in one call.
    Sets the binary path then returns: format/arch, strings summary, imports.
    Use this as the first step when given a binary path to analyze.

    path: absolute path to the binary file (e.g. 'C:\\crackme\\challenge.exe').
    """
    global _binary
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"
    _binary = str(p.resolve())
    _save_state(_binary)

    parts: list[str] = [f"Binary set: {_binary}", ""]

    # Static info
    try:
        from aira.static_analysis import get_basic_info
        info = get_basic_info(_binary)
        parts += [
            f"Format: {info.format}",
            f"Architecture: {info.architecture}",
            f"Imagebase: {info.imagebase_hex}",
            f"Entrypoint: {info.entrypoint_hex}",
            f"Sections ({len(info.sections)}): " + ", ".join(s["name"] for s in info.sections),
            f"Imports ({len(info.imports)}): " + ", ".join(
                i.get("symbol", "") for i in info.imports[:40] if i.get("symbol")
            ),
            "",
        ]
    except Exception as exc:
        parts.append(f"Static info error: {exc}\n")

    # Strings (top 50)
    try:
        from aira.static_analysis import extract_strings as _ext
        from aira.ghidra.client import _filter_strings
        raw = _ext(_binary, min_len=4)
        filtered = _filter_strings(raw)
        parts.append(f"Strings: {len(raw)} extracted, {len(filtered)} relevant (top 50 shown):")
        parts += filtered[:50]
        parts.append("")
    except Exception as exc:
        parts.append(f"Strings error: {exc}\n")

    return "\n".join(parts)


# ── Level 5 — WAR / Java analysis ─────────────────────────────────────────────

@mcp.tool()
def analyze_war_file(path: str) -> str:
    """
    Analyze a WAR (Java Web Application Archive) file for security issues.

    Performs: structure extraction, web.xml analysis, vulnerable library detection,
    webshell scanning, dangerous Java API detection, secrets/credentials search,
    entropy analysis, and YARA rule matching.

    path: absolute path to the .war file (e.g. 'C:\\samples\\app.war').
    Returns a security summary with risk score.
    """
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"
    if not p.suffix.lower() in (".war", ".jar", ".ear", ".zip"):
        return f"Error: expected a WAR/JAR/EAR file, got: {p.suffix}"

    try:
        from aira.analyzers.war_analyzer import analyze_war, format_war_for_llm
        result = analyze_war(str(p))
        if "error" in result:
            return f"Error: {result['error']}"
        return format_war_for_llm(result, max_chars=4000)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def war_detailed_analysis(path: str) -> str:
    """
    Run a detailed WAR analysis and return the full JSON results.
    Use analyze_war_file() first for a summary, then this for full details.

    path: absolute path to the .war file.
    """
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"

    try:
        from aira.analyzers.war_analyzer import analyze_war
        result = analyze_war(str(p))
        if "error" in result:
            return f"Error: {result['error']}"

        # Format key sections
        parts: list[str] = []
        parts.append(f"WAR: {result.get('filename')} | Risk: {result.get('verdict', '?')}")
        parts.append(f"SHA256: {result.get('sha256', '?')}")
        parts.append(f"Files: {result.get('total_files', 0)} | "
                     f"Classes: {len(result.get('java_classes', []))} | "
                     f"JSPs: {len(result.get('jsp_files', []))} | "
                     f"JARs: {len(result.get('lib_jars', []))}")

        # Web.xml
        web_xml = result.get("web_xml", {})
        if web_xml and "error" not in web_xml:
            servlets = web_xml.get("servlets", [])
            filters = web_xml.get("filters", [])
            parts.append(f"\nServlets ({len(servlets)}):")
            for s in servlets[:20]:
                urls = ", ".join(s.get("url_patterns", []))
                parts.append(f"  {s['name']}: {s['class']} [{urls}]")
            if filters:
                parts.append(f"Filters ({len(filters)}):")
                for f in filters[:10]:
                    parts.append(f"  {f['name']}: {f['class']}")
            issues = web_xml.get("issues", [])
            if issues:
                parts.append(f"Issues ({len(issues)}):")
                for i in issues:
                    parts.append(f"  - {i}")

        # Vulnerable libs
        vulns = result.get("vulnerable_libs", [])
        if vulns:
            parts.append(f"\nVulnerable libraries ({len(vulns)}):")
            for v in vulns:
                parts.append(f"  {v['jar']} — {v['cve']}: {v['desc']} [{v['risk']}]")

        # Dangerous APIs
        apis = result.get("dangerous_apis", [])
        if apis:
            parts.append(f"\nDangerous APIs ({len(apis)}):")
            for a in apis[:30]:
                parts.append(f"  [{a['risk']}] {a['api']} in {a['source']}: {a['description']}")

        # Webshells
        ws = result.get("webshell_indicators", [])
        if ws:
            parts.append(f"\nWebshell indicators ({len(ws)}):")
            for w in ws:
                parts.append(f"  [{w['risk']}] {w['pattern']} in {w['source']}")

        # Secrets
        secrets = result.get("secrets_found", [])
        if secrets:
            parts.append(f"\nSecrets/Credentials ({len(secrets)}):")
            for s in secrets[:15]:
                parts.append(f"  {s['type']} in {s['source']}")

        # JARs list
        jars = result.get("lib_jars", [])
        if jars:
            parts.append(f"\nAll JARs ({len(jars)}):")
            for j in jars[:40]:
                parts.append(f"  {j}")

        return "\n".join(parts)
    except Exception as exc:
        return f"Error: {exc}"


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="AIRA unified MCP server")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="sse")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8082)
    args = parser.parse_args()

    if args.transport == "sse":
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.settings.log_level = "WARNING"
        print(f"AIRA MCP server on http://{args.host}:{args.port}/sse")
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
