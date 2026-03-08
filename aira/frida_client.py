"""
AIRA Frida Client — dynamic analysis via Frida.

Frida intercepts strcmp/strncmp calls at runtime to capture the
actual password being compared, without needing the source code.

Usage:
  from aira.frida_client import intercept_strcmp, is_frida_available
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import os
from pathlib import Path

_FRIDA_SCRIPT = r"""
'use strict';

var results = [];
var hooks = ['strcmp', 'strncmp', 'wcscmp', 'wcsncmp',
             'memcmp', '_stricmp', '_strnicmp'];

hooks.forEach(function(name) {
    try {
        var sym = Module.findExportByName(null, name);
        if (!sym) return;
        Interceptor.attach(sym, {
            onEnter: function(args) {
                try {
                    var s1 = args[0].readUtf8String(64);
                    var s2 = args[1].readUtf8String(64);
                    if (s1 && s2 && s1.length > 0 && s2.length > 0) {
                        send({fn: name, s1: s1, s2: s2});
                    }
                } catch(e) {}
            }
        });
    } catch(e) {}
});

setTimeout(function() { send({done: true}); }, 5000);
"""


def is_frida_available() -> bool:
    """Return True if frida-tools is installed."""
    try:
        import frida  # noqa: F401
        return True
    except ImportError:
        return False


def intercept_strcmp(
    binary_path: str,
    stdin_input: str = "\n",
    timeout: int = 10,
) -> list[dict]:
    """
    Launch binary with Frida, hook all comparison functions,
    capture s1/s2 pairs that might contain the password.

    Returns list of {fn, s1, s2} dicts.
    """
    if not is_frida_available():
        return []

    try:
        import frida

        script_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False
        )
        script_file.write(_FRIDA_SCRIPT)
        script_file.close()

        results: list[dict] = []

        def on_message(message, data):
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if not payload.get("done"):
                    results.append(payload)

        device = frida.get_local_device()
        pid = device.spawn([binary_path], stdio="pipe")
        session = device.attach(pid)
        script = session.create_script(_FRIDA_SCRIPT)
        script.on("message", on_message)
        script.load()
        device.resume(pid)

        import time
        time.sleep(min(timeout, 8))

        try:
            session.detach()
        except Exception:
            pass

        os.unlink(script_file.name)
        return results

    except Exception:
        return []


def frida_find_password(binary_path: str) -> str:
    """
    Run the binary with Frida and look for strcmp calls where one
    argument looks like a user-provided input and the other is a
    hardcoded secret.

    Returns a context string for the LLM, or empty string if Frida
    is unavailable or finds nothing.
    """
    if not is_frida_available():
        return ""

    comparisons = intercept_strcmp(binary_path, stdin_input="AAAABBBB\n")
    if not comparisons:
        return ""

    lines = ["[Level 4 — Frida Dynamic Analysis]"]
    lines.append(f"Intercepted {len(comparisons)} string comparisons:")
    for i, c in enumerate(comparisons[:20]):
        fn = c.get("fn", "strcmp")
        s1 = c.get("s1", "")
        s2 = c.get("s2", "")
        lines.append(f"  [{fn}] '{s1}' vs '{s2}'")
        # Heuristic: if one side is our input probe, the other is the password
        if "AAAA" in s1 and s2 and len(s2) < 32:
            lines.append(f"  → Likely password: '{s2}'")
        elif "AAAA" in s2 and s1 and len(s1) < 32:
            lines.append(f"  → Likely password: '{s1}'")

    return "\n".join(lines)
