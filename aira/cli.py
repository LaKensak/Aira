from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from aira import static_analysis
from aira.static_detection import scan_with_yara
from aira.dynamic.frida_manager import attach_and_inject, spawn_and_inject
from aira.symexec.client import solve as sym_solve, SolveRequest
from aira.ai.client import explain as ai_explain
from aira.ai.langflow_client import LangflowChatSession, LangflowClient, LangflowError
from aira.config import (
    BASE_DIR,
    LANGFLOW_API_KEY,
    LANGFLOW_BASE_URL,
    LANGFLOW_ENDPOINT,
    LANGFLOW_FLOW_ID,
    OUTPUT_DIR,
)
from aira.utils import console, save_json, save_text, warn
from aira.ghidra import run_bridge, GhidraClient
from aira.ghidra.client import cascade_mcp_context

# New modules for improved error handling and validation
from aira.logging_config import setup_logging, get_logger
from aira.exceptions import (
    AIRAError,
    ValidationError,
    BinaryNotFoundError,
    ServiceError,
    ConfigError,
)
from aira.validators import (
    hex_address,
    existing_binary,
    existing_file,
    valid_pid,
    temperature_value,
    probability_value,
    positive_int,
)

logger = get_logger(__name__)


def cmd_static_info(args: argparse.Namespace) -> int:
    logger.info(f"Analyzing binary: {args.binary}")
    try:
        info = static_analysis.get_basic_info(str(args.binary))
        out = OUTPUT_DIR / "static_info.json"
        save_json(out, json.loads(json.dumps(info, default=lambda o: o.__dict__)))
        logger.debug(f"Static info saved to {out}")
        console.print(f"Static info -> {out}")
        return 0
    except Exception as exc:
        logger.exception(f"Failed to analyze binary: {args.binary}")
        raise ServiceError(f"Analysis failed: {exc}") from exc


def cmd_attach(args: argparse.Namespace) -> int:
    logger.info(f"Attaching to PID {args.pid} with script {args.script}")
    try:
        res = attach_and_inject(args.pid, str(args.script))
        out = OUTPUT_DIR / f"attach_{res.pid}.log"
        save_text(out, "\n".join(res.script_message_log))
        logger.debug(f"Attach log saved to {out}")
        console.print(f"Attached to {res.pid}. Log -> {out}")
        return 0
    except Exception as exc:
        logger.exception(f"Failed to attach to PID {args.pid}")
        raise ServiceError(f"Frida attach failed: {exc}") from exc


def cmd_solve(args: argparse.Namespace) -> int:
    logger.info(f"Solving for address {args.address} in {args.binary}")
    try:
        req = SolveRequest(
            binary_path=str(args.binary),
            addr_target=args.address,
            addr_avoid=args.avoid or [],
            stdin_len=args.stdin_len,
            input_mode=getattr(args, "mode", "stdin"),
            argv_len=getattr(args, "argv_len", 32),
        )
        logger.debug(f"Solve request: {req}")
        data = sym_solve(req)
        out = OUTPUT_DIR / "solve.json"
        save_json(out, data)
        logger.debug(f"Solution saved to {out}")
        console.print(f"Solution saved -> {out}")
        return 0
    except Exception as exc:
        logger.exception(f"Symbolic execution failed")
        raise ServiceError(f"Symbolic execution failed: {exc}") from exc


def cmd_ai_explain(args: argparse.Namespace) -> int:
    logger.info(f"AI explain with provider: {args.provider or 'default'}")
    try:
        if args.file:
            code = args.file.read_text(encoding="utf-8")
            logger.debug(f"Read code from file: {args.file}")
        else:
            code = args.code

        explanation = ai_explain(code, provider=args.provider)
        out = OUTPUT_DIR / "ai_explain.txt"
        save_text(out, explanation)
        logger.debug(f"Explanation saved to {out}")
        console.print(f"Explanation saved -> {out}")
        return 0
    except Exception as exc:
        logger.exception("AI explain failed")
        raise ServiceError(f"AI explain failed: {exc}") from exc


def cmd_launch_patched(args: argparse.Namespace) -> int:
    logger.info(f"Launching patched binary: {args.binary}")
    try:
        script = Path(__file__).resolve().parent / "dynamic" / "scripts" / "anti_debug.js"
        if not script.exists():
            raise ConfigError(f"Anti-debug script not found: {script}")
        pid = spawn_and_inject(str(args.binary), str(script), argv=args.argv)
        logger.debug(f"Spawned with PID {pid}")
        console.print(f"Spawned {args.binary} with anti-debug hooks. PID={pid}")
        return 0
    except ConfigError:
        raise
    except Exception as exc:
        logger.exception(f"Failed to launch patched binary")
        raise ServiceError(f"Launch failed: {exc}") from exc


def cmd_scan_antidebug(args: argparse.Namespace) -> int:
    logger.info(f"Scanning for anti-debug techniques: {args.binary}")
    rules = BASE_DIR / "signatures" / "anti_debug.yar"
    if not rules.exists():
        raise ConfigError(f"YARA rule file not found: {rules}")
    try:
        matches = scan_with_yara(str(args.binary), rules)
        out = OUTPUT_DIR / "anti_debug_matches.json"
        save_json(out, {"matches": matches})
        logger.debug(f"Scan results saved to {out}")
        console.print(f"Anti-debug scan -> {out}")
        return 0
    except Exception as exc:
        logger.exception("YARA scan failed")
        raise ServiceError(f"YARA scan failed: {exc}") from exc


def cmd_graph(args: argparse.Namespace) -> int:
    logger.info(f"Generating CFG for {args.address} in {args.binary}")
    try:
        from aira.config import SYMEXEC_URL
        from aira.http_client import sync_post

        r = sync_post(f"{SYMEXEC_URL}/cfg", json={
            "binary_path": str(args.binary),
            "address": args.address,
        }, timeout=600)
        r.raise_for_status()
        data = r.json()

        dot_path = OUTPUT_DIR / "cfg.dot"
        save_text(dot_path, data.get("dot", ""))
        logger.debug(f"CFG DOT saved to {dot_path}")

        if args.png:
            try:
                import graphviz
                graphviz.Source(data.get("dot", "")).render(str(OUTPUT_DIR / "cfg"), format="png", cleanup=True)
                logger.debug("CFG PNG generated")
            except Exception as e:
                logger.warning(f"Graphviz PNG render failed: {e}")
                warn(f"Graphviz PNG render failed: {e}")

        console.print(f"CFG DOT -> {dot_path}")
        return 0
    except Exception as exc:
        logger.exception("CFG generation failed")
        raise ServiceError(f"CFG generation failed: {exc}") from exc


def cmd_ai_monitor(args: argparse.Namespace) -> int:
    logger.info(f"Monitoring function '{args.name}' in PID {args.pid}")
    try:
        import frida
        device = frida.get_local_device()
        session = device.attach(args.pid)

        script_path = Path(__file__).resolve().parent / "dynamic" / "scripts" / "monitor_function.js"
        if not script_path.exists():
            raise ConfigError(f"Monitor script not found: {script_path}")

        code = script_path.read_text(encoding="utf-8")
        script = session.create_script(code)
        log: list[str] = []

        def on_message(message, data):
            payload = str(message.get("payload"))
            log.append(payload)
            logger.debug(f"Monitor: {payload}")
            console.print(payload)

        script.on("message", on_message)
        script.load()
        script.exports.monitor(args.name)
        console.print("Monitoring active. Press Ctrl+C to stop.")

        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
        return 0
    except Exception as exc:
        logger.exception("Monitoring failed")
        raise ServiceError(f"Monitoring failed: {exc}") from exc


def cmd_find_path_dynamic(args: argparse.Namespace) -> int:
    # For now, reuse symbolic solver as an improved version
    return cmd_solve(args)


def cmd_analyze_war(args: argparse.Namespace) -> int:
    logger.info(f"Analyzing WAR file: {args.war_file}")
    try:
        from aira.analyzers.war_analyzer import analyze_war, format_war_for_llm
        result = analyze_war(str(args.war_file))
        if "error" in result:
            warn(result["error"])
            return 1

        # Sauvegarder le JSON complet
        out_json = OUTPUT_DIR / "war_analysis.json"
        save_json(out_json, result)

        # Sauvegarder le résumé texte
        out_txt = OUTPUT_DIR / "war_analysis.txt"
        summary = format_war_for_llm(result, max_chars=10000)
        save_text(out_txt, summary)

        # YARA scan si disponible
        yara_out: list[dict] = []
        rules_path = BASE_DIR / "signatures" / "java_war.yar"
        if rules_path.exists():
            try:
                yara_matches = scan_with_yara(str(args.war_file), rules_path)
                if yara_matches:
                    yara_out = yara_matches
                    yara_file = OUTPUT_DIR / "war_yara_matches.json"
                    save_json(yara_file, {"matches": yara_matches})
                    logger.debug(f"WAR YARA matches saved to {yara_file}")
            except Exception as e:
                logger.warning(f"WAR YARA scan failed: {e}")

        # Afficher le résumé
        console.print(f"\n{summary}")
        if yara_out:
            console.print(f"\n[YARA] {len(yara_out)} règle(s) Java/WAR déclenchée(s):")
            for m in yara_out[:10]:
                console.print(f"  • {m['rule']} [{m.get('meta', {}).get('severity', '?')}] — {m.get('meta', {}).get('description', '')}")

        console.print(f"\nJSON détaillé -> {out_json}")
        console.print(f"Résumé texte  -> {out_txt}")
        return 0
    except Exception as exc:
        logger.exception("WAR analysis failed")
        raise ServiceError(f"WAR analysis failed: {exc}") from exc


def cmd_ghidra_mcp(args: argparse.Namespace) -> int:
    return run_bridge(
        transport=args.transport,
        ghidra_server=args.ghidra_server,
        host=args.mcp_host,
        port=args.mcp_port,
    )


def cmd_mcp_server(args: argparse.Namespace) -> int:
    from aira.mcp_server import main as mcp_main
    import sys
    sys.argv = ["aira-mcp"]
    if args.transport:
        sys.argv += ["--transport", args.transport]
    if args.mcp_host:
        sys.argv += ["--host", args.mcp_host]
    if args.mcp_port:
        sys.argv += ["--port", str(args.mcp_port)]
    mcp_main()
    return 0


def cmd_ghidra_flow(args: argparse.Namespace) -> int:
    logger.info("Starting Ghidra LangFlow session")

    # Temperature and top_p are now validated by argparse validators

    base_url = (args.langflow_url or LANGFLOW_BASE_URL or "").strip()
    flow_id = (args.flow_id or LANGFLOW_FLOW_ID or "").strip()
    endpoint = args.langflow_endpoint or LANGFLOW_ENDPOINT
    api_key = args.langflow_api_key or LANGFLOW_API_KEY

    if not base_url:
        raise ConfigError("LangFlow base URL is not configured. Set LANGFLOW_BASE_URL or use --langflow-url.")
    if not flow_id:
        raise ConfigError("LangFlow flow id is not configured. Set LANGFLOW_FLOW_ID or use --flow-id.")

    target_path: Path | None = None
    if args.binary:
        target_path = Path(args.binary).expanduser()
        if not target_path.exists():
            raise BinaryNotFoundError(str(target_path))
        target_path = target_path.resolve()
        logger.debug(f"Target binary: {target_path}")

    try:
        client = LangflowClient(
            base_url=base_url,
            flow_id=flow_id,
            endpoint=endpoint,
            api_key=api_key,
            timeout=args.timeout,
        )
        logger.debug(f"LangFlow client created: {client.url}")
    except ValueError as exc:
        raise ConfigError(f"LangFlow configuration error: {exc}") from exc

    bridge_proc: subprocess.Popen[bytes] | None = None
    if args.bridge:
        bridge_result = run_bridge(
            transport=args.transport,
            ghidra_server=args.ghidra_server,
            host=args.mcp_host,
            port=args.mcp_port,
            wait=False,
        )
        if isinstance(bridge_result, int):
            if bridge_result != 0:
                return bridge_result
        else:
            bridge_proc = bridge_result

    def cleanup_bridge() -> None:
        if not bridge_proc:
            return
        if bridge_proc.poll() is not None:
            return
        console.print("Stopping Ghidra MCP bridge...")
        bridge_proc.terminate()
        try:
            bridge_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            bridge_proc.kill()

    ghidra_url = (args.ghidra_server or "http://127.0.0.1:8080/").rstrip("/") + "/"
    ghidra_client = GhidraClient(base_url=ghidra_url)
    ghidra_available = ghidra_client.is_available()
    if ghidra_available:
        logger.debug(f"Ghidra REST plugin reachable at {ghidra_url}")
    else:
        logger.warning(f"Ghidra REST plugin not reachable at {ghidra_url} — mcp_result will be empty")
        console.print(f"[yellow]Warning: Ghidra not reachable at {ghidra_url}. Responses may be incomplete.[/]")

    session = LangflowChatSession(
        client,
        system_prompt=args.system,
        temperature=args.temperature,
        top_p=args.top_p,
    )

    static_context = f"Binary under analysis: {target_path}" if target_path else ""
    if target_path:
        session.add_message("system", f"Target binary path: {target_path}")

    output_path = Path(args.output) if args.output else OUTPUT_DIR / "ghidra_flow_chat.json"

    def save_transcript() -> None:
        if not args.save:
            return
        messages = session.transcript()
        if not messages:
            return
        save_json(
            output_path,
            {
                "base_url": client.base_url,
                "flow_id": client.flow_id,
                "temperature": session.temperature,
                "top_p": session.top_p,
                "binary": str(target_path) if target_path else None,
                "messages": messages,
            },
        )
        console.print(f"Transcript saved -> {output_path}")

    def show_response(resp: dict) -> None:
        model = resp.get("model") or "langflow"
        answer = (resp.get("output_text") or "").strip()
        console.print(f"Model: {model}")
        if answer:
            console.print(answer)
        else:
            console.print("[yellow]Received empty response from LangFlow.[/]")

    console.print(f"LangFlow flow: {client.flow_id} ({client.url})")
    if target_path:
        console.print(f"Target binary: {target_path}")

    exit_code = 0
    prompt_text: str | None = None
    try:
        if args.file:
            try:
                prompt_text = Path(args.file).read_text(encoding="utf-8")
            except OSError as exc:
                raise RuntimeError(f"Failed to read prompt file {args.file}: {exc}") from exc
        elif args.prompt:
            prompt_text = args.prompt
        elif not sys.stdin.isatty():
            prompt_text = sys.stdin.read()

        if prompt_text is not None and not prompt_text.strip():
            raise RuntimeError("Prompt is empty.")

        symexec_url = str(getattr(__import__("aira.config", fromlist=["SYMEXEC_URL"]), "SYMEXEC_URL", "http://127.0.0.1:8001"))

        if prompt_text is not None:
            mcp_result = cascade_mcp_context(
                str(target_path), question=prompt_text,
                ghidra_client=ghidra_client if ghidra_available else None,
                symexec_url=symexec_url,
            ) if target_path else ""
            response = session.ask(prompt_text, mcp_result=mcp_result, context=static_context)
            show_response(response)
        else:
            console.print("Interactive LangFlow session. Type ':q' or 'exit' to quit.")
            while True:
                try:
                    user_input = console.input("[bold cyan]You[/]> ")
                except EOFError:
                    console.print()
                    break
                except KeyboardInterrupt:
                    console.print()
                    break
                text = user_input.strip()
                if not text:
                    continue
                if text.lower() in {"exit", "quit", ":q"}:
                    break
                mcp_result = cascade_mcp_context(
                    str(target_path), question=text,
                    ghidra_client=ghidra_client if ghidra_available else None,
                    symexec_url=symexec_url,
                ) if target_path else ""
                response = session.ask(text, mcp_result=mcp_result, context=static_context)
                show_response(response)
    except LangflowError as exc:
        warn(str(exc))
        exit_code = 1
    except RuntimeError as exc:
        warn(str(exc))
        exit_code = 1
    except KeyboardInterrupt:
        console.print()
    finally:
        try:
            save_transcript()
        finally:
            cleanup_bridge()
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aira", description="AI-Assisted Reversing Analyser (Python)")

    # Global options
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    p.add_argument("--log-file", type=Path, help="Write logs to file")

    sub = p.add_subparsers(dest="cmd")

    # F1/F1.2: static info
    s = sub.add_parser("static-info", help="Parse binary and dump basic info")
    s.add_argument("binary", type=existing_binary, help="Binary file to analyze")
    s.set_defaults(func=cmd_static_info)

    # F2 (attach & inject JS)
    s = sub.add_parser("attach", help="Attach to PID and inject Frida JS")
    s.add_argument("pid", type=valid_pid, help="Process ID to attach to")
    s.add_argument("script", type=existing_file, help="Path to frida JS script")
    s.set_defaults(func=cmd_attach)

    # F3: symbolic solve
    s = sub.add_parser("solve", help="Symbolically find input to reach address")
    s.add_argument("binary", type=existing_binary, help="Binary file to analyze")
    s.add_argument("address", type=hex_address, help="Target address in hex, e.g. 0x401234")
    s.add_argument("--avoid", nargs="*", type=hex_address, help="Addresses to avoid (hex)")
    s.add_argument("--stdin-len", type=positive_int, default=64, help="Symbolic stdin length")
    s.add_argument("--mode", choices=["stdin", "argv"], default="stdin", help="Input mode: stdin or argv[1]")
    s.add_argument("--argv-len", type=positive_int, default=32, help="Symbolic argv[1] length if --mode argv")
    s.set_defaults(func=cmd_solve)

    # F4: AI explain
    s = sub.add_parser("ai-explain", help="Explain a block of assembly/code with AI")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", type=existing_file, help="File containing code to explain")
    g.add_argument("--code", help="Code string to explain")
    s.add_argument("--provider", choices=["langflow", "openai", "azure"], default=None)
    s.set_defaults(func=cmd_ai_explain)

    # F5: launch patched (anti-debug)
    s = sub.add_parser("launch-patched", help="Spawn target with anti-debug bypass hooks")
    s.add_argument("binary", type=existing_binary, help="Binary to launch")
    s.add_argument("argv", nargs=argparse.REMAINDER, help="Arguments to pass to binary")
    s.set_defaults(func=cmd_launch_patched)

    # F6/F8: scan anti-debug (static)
    s = sub.add_parser("scan-antidebug", help="Scan binary for anti-debugging techniques (YARA)")
    s.add_argument("binary", type=existing_binary, help="Binary file to scan")
    s.set_defaults(func=cmd_scan_antidebug)

    # F7: CFG graph
    s = sub.add_parser("graph", help="Build CFG for function/address via angr service")
    s.add_argument("binary", type=existing_binary, help="Binary file to analyze")
    s.add_argument("address", type=hex_address, help="Function address in hex")
    s.add_argument("--png", action="store_true", help="Generate PNG output")
    s.set_defaults(func=cmd_graph)

    # F9: AI monitor function calls
    s = sub.add_parser("ai-monitor", help="Monitor function by name or address using Frida")
    s.add_argument("pid", type=valid_pid, help="Process ID to monitor")
    s.add_argument("name", help="Function name or address to monitor")
    s.set_defaults(func=cmd_ai_monitor)

    # F10: dynamic path finding (reuse solve for now)
    s = sub.add_parser("find-path-dynamic", help="Dynamic+symbolic path to address")
    s.add_argument("binary", type=existing_binary, help="Binary file to analyze")
    s.add_argument("address", type=hex_address, help="Target address in hex")
    s.add_argument("--avoid", nargs="*", type=hex_address, help="Addresses to avoid")
    s.add_argument("--stdin-len", type=positive_int, default=64)
    s.add_argument("--mode", choices=["stdin", "argv"], default="stdin")
    s.add_argument("--argv-len", type=positive_int, default=32)
    s.set_defaults(func=cmd_find_path_dynamic)

    # WAR analysis
    s = sub.add_parser("analyze-war", help="Analyze a WAR (Java Web Application Archive) for security issues")
    s.add_argument("war_file", type=existing_file, help="WAR file to analyze")
    s.set_defaults(func=cmd_analyze_war)

    # Ghidra MCP bridge runner
    s = sub.add_parser("ghidra-mcp", help="Launch the Ghidra MCP bridge server")
    s.add_argument("--transport", choices=["stdio", "sse"], default=None)
    s.add_argument("--ghidra-server", default=None, help="Ghidra HTTP plugin endpoint, e.g. http://127.0.0.1:8080/")
    s.add_argument("--mcp-host", default=None, help="Host for SSE transport")
    s.add_argument("--mcp-port", type=positive_int, default=None, help="Port for SSE transport")
    s.set_defaults(func=cmd_ghidra_mcp)

    # AIRA unified MCP server
    s = sub.add_parser("mcp-server", help="Launch the unified AIRA MCP server (all tools via SSE)")
    s.add_argument("--transport", choices=["stdio", "sse"], default="sse")
    s.add_argument("--mcp-host", default="127.0.0.1", help="Host for SSE transport")
    s.add_argument("--mcp-port", type=positive_int, default=8082, help="Port for SSE transport (default 8082)")
    s.set_defaults(func=cmd_mcp_server)

    # Ghidra LangFlow assistant
    s = sub.add_parser("ghidra-flow", help="Chat with the LangFlow-powered Ghidra assistant")
    mg = s.add_mutually_exclusive_group()
    mg.add_argument("-p", "--prompt", help="Send a single prompt to the flow")
    mg.add_argument("-f", "--file", type=existing_file, help="Read the prompt from a text file")
    s.add_argument("--system", help="Optional system prompt for the conversation")
    s.add_argument("--flow-id", default=None, help="Override LANGFLOW_FLOW_ID for this run")
    s.add_argument("--langflow-url", default=None, help="Override LANGFLOW_BASE_URL for this run")
    s.add_argument("--langflow-endpoint", default=None, help="Override LANGFLOW_ENDPOINT for this run")
    s.add_argument("--langflow-api-key", default=None, help="Override LANGFLOW_API_KEY for this run")
    s.add_argument("--temperature", type=temperature_value, default=0.2, help="Sampling temperature (0.0-2.0)")
    s.add_argument("--top-p", type=probability_value, default=1.0, help="Top-p nucleus sampling (0.0-1.0)")
    s.add_argument("--timeout", type=positive_int, default=60, help="LangFlow request timeout in seconds")
    s.add_argument(
        "--output",
        default=None,
        help="Path to store the chat transcript (default: output/ghidra_flow_chat.json)",
    )
    s.add_argument("--no-save", dest="save", action="store_false", help="Disable transcript saving")
    s.add_argument("--transport", choices=["stdio", "sse"], default=None, help="Bridge transport override")
    s.add_argument("--ghidra-server", default=None, help="Ghidra HTTP plugin endpoint, e.g. http://127.0.0.1:8080/")
    s.add_argument("--mcp-host", default=None, help="Host for SSE transport")
    s.add_argument("--mcp-port", type=positive_int, default=None, help="Port for SSE transport")
    s.add_argument("--no-bridge", dest="bridge", action="store_false", help="Do not auto-start the Ghidra MCP bridge")
    s.add_argument("binary", nargs="?", help="Optional binary path to analyse within Ghidra/LangFlow")
    s.set_defaults(func=cmd_ghidra_flow, bridge=True, save=True)

    return p


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point for the AIRA CLI.

    Exit codes:
        0: Success
        1: Runtime error (service, IO, execution)
        2: Invalid usage (bad arguments, missing files)
    """
    argv = argv or sys.argv[1:]
    p = build_parser()

    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        # argparse exits with code 2 for invalid arguments
        return 2 if e.code != 0 else 0

    # Setup logging based on --debug flag
    log_level = "DEBUG" if getattr(args, "debug", False) else "INFO"
    log_file = getattr(args, "log_file", None)
    setup_logging(level=log_level, log_file=log_file)

    if not hasattr(args, "func"):
        p.print_help()
        return 2  # No command specified

    logger.debug(f"Command: {args.cmd}, Args: {args}")

    try:
        return args.func(args)
    except ValidationError as exc:
        logger.error(f"Validation error: {exc}")
        warn(str(exc))
        return exc.exit_code  # 2
    except ServiceError as exc:
        logger.error(f"Service error: {exc}")
        warn(str(exc))
        return exc.exit_code  # 1
    except ConfigError as exc:
        logger.error(f"Configuration error: {exc}")
        warn(str(exc))
        return exc.exit_code  # 1
    except AIRAError as exc:
        logger.error(f"Error: {exc}")
        warn(str(exc))
        return exc.exit_code
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        console.print()
        return 130  # Standard exit code for SIGINT
    except Exception as exc:
        logger.exception(f"Unexpected error: {exc}")
        warn(f"Unexpected error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
