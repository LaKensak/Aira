"""Thin HTTP client for the Ghidra REST plugin (default port 8080)."""
from __future__ import annotations

from pathlib import Path

import requests
from urllib.parse import urljoin

DEFAULT_GHIDRA_URL = "http://127.0.0.1:8080/"


class GhidraClient:
    """Query the Ghidra HTTP REST plugin directly to build MCP context."""

    def __init__(self, base_url: str = DEFAULT_GHIDRA_URL, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self._session = requests.Session()

    def _get(self, endpoint: str, params: dict | None = None) -> list[str]:
        try:
            resp = self._session.get(
                urljoin(self.base_url, endpoint),
                params=params,
                timeout=self.timeout,
            )
            if resp.ok:
                return [line for line in resp.text.splitlines() if line.strip()]
            return []
        except requests.RequestException:
            return []

    def is_available(self) -> bool:
        try:
            resp = self._session.get(
                urljoin(self.base_url, "methods"),
                params={"offset": 0, "limit": 1},
                timeout=3,
            )
            return resp.ok
        except requests.RequestException:
            return False

    def list_functions(self, limit: int = 500) -> list[str]:
        # /list_functions retourne "name at address" — plus complet que /methods
        result = self._get("list_functions")
        if not result:
            result = self._get("methods", {"offset": 0, "limit": limit})
        return result

    def list_strings(self) -> list[str]:
        return self._get("strings")

    def list_imports(self) -> list[str]:
        return self._get("imports")

    def decompile(self, name: str) -> list[str]:
        # GhidraMCP: POST /decompile with function name in request body
        try:
            resp = self._session.post(
                urljoin(self.base_url, "decompile"),
                data=name.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
                timeout=self.timeout,
            )
            if resp.ok:
                return [line for line in resp.text.splitlines() if line.strip()]
            return []
        except requests.RequestException:
            return []

    def decompile_at(self, address: str) -> list[str]:
        # GhidraMCP: GET /decompile_function?address=<hex>
        return self._get("decompile_function", {"address": address})

    def build_mcp_context(self, question: str = "") -> str:
        """
        Collect data from Ghidra and format it as a context string for the LLM.

        Always fetches: function list, strings, imports.
        Also decompiles any function whose name appears explicitly in the question.
        Returns an empty string if Ghidra is unreachable.
        """
        parts: list[str] = []

        functions = self.list_functions(limit=100)
        if functions:
            parts.append(
                f"### Functions ({len(functions)} found)\n" + "\n".join(functions[:50])
            )

        strings = self.list_strings()
        if strings:
            parts.append(
                f"### Strings ({len(strings)} found)\n" + "\n".join(strings[:200])
            )

        imports = self.list_imports()
        if imports:
            parts.append("### Imports\n" + "\n".join(imports[:50]))

        # Decompile any function explicitly named in the question
        q_lower = question.lower()
        for func in functions:
            fname = func.strip()
            if fname and fname.lower() in q_lower:
                decompiled = self.decompile(fname)
                if decompiled:
                    parts.append(
                        f"### Decompiled: {fname}\n" + "\n".join(decompiled)
                    )

        return "\n\n".join(parts)


def _filter_strings(strings: list[str], question: str = "") -> list[str]:
    """
    Keep only strings relevant for RE analysis.
    Excludes DLL names, paths, long debug strings, and compiler noise.
    Prioritizes short alphanumeric strings likely to be passwords/keys.
    """
    import re
    noise = re.compile(
        r"(\.dll|\.exe|\.pdb|\.obj|vcruntime|msvcp|kernel32|ntdll|"
        r"__security|@?\?\?|\\Device\\|C:\\|[Mm]icrosoft|Visual C\+\+|"
        r"Runtime|__acrt|_RTC|_CRT|AppPolicyGet|"
        # Windows API / PE structure noise
        r"CriticalSection|VirtualProtect|VirtualQuery|VirtualAlloc|"
        r"IsDebugger|ExceptionCode|ExceptionFlags|ExceptionAddress|"
        r"NumberParameters|ExceptionInformation|ContextFlags|EFlags|"
        r"VectorRegister|DebugControl|LastBranch|LastException|"
        r"ControlWord|StatusWord|TagWord|ErrorOpcode|ErrorOffset|"
        r"DataOffset|DataSelector|FloatRegisters|XmmRegisters|"
        r"FiberData|SubSystemTib|ArbitraryUser|StackBase|StackLimit|"
        r"NumberOfSections|TimeDateStamp|PointerToSymbol|SizeOfOptional|"
        r"VirtualAddress|BaseOfData|FileHeader|OptionalHeader|"
        r"pDOSHeader|pPEHeader|pNTHeader|mainCRTStartup|WinMainCRT|"
        r"Natexit|EtagCOINIT|MessageBox|TlsGetValue|GetLastError|"
        r"EnterCritical|LeaveCritical|ExceptionList|P[1-6]Home|"
        r"Reserved[0-9]|Header|Legacy|FloatSave|ContextRecord|"
        # C++ locale/type noise
        r"NSt\d|St\d+[a-z]|Infinity|NaN|"
        # Calendar / locale noise (days, months)
        r"^(Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|"
        r"January|February|March|April|May|June|July|August|"
        r"September|October|November|December)$|"
        # Win32 API names that are pure noise
        r"^(AddAtomA|CloseHandle|CreateEvent|CreateMutex|CreateSemaphore|"
        r"DuplicateHandle|FindAtom|GetAtom|GetCurrent|GetHandle|GetProcAddr|"
        r"GetStartup|GetThread|GetTick|QueryPerf|RaiseException|Release|"
        r"ResetEvent|Resume|Rtl|SetEvent|SetLast|SetThread|Suspend|"
        r"Terminate|TlsAlloc|TlsSet|Unhandled|VectorCtrl|"
        r"lpReserved|lpDesktop|dwX|dwY|dwFill|wShow|hStd|tagCOINIT|"
        r"fUser|stUser|BaseAddr|AllocBase|ErrorSel|FltSave|"
        r"NumberOf|Characteristics|Signature|Machine|Version|Handler))",
        re.IGNORECASE,
    )
    results: list[str] = []
    q_lower = question.lower()
    for s in strings:
        if noise.search(s):
            continue
        if len(s) < 4 or len(s) > 64:
            continue
        # Skip strings that look like camelCase Windows API names (long, no spaces, lots of caps)
        if len(s) > 15 and s[0].isupper() and sum(1 for c in s if c.isupper()) > 3 and " " not in s:
            # Keep only if it looks like a potential password (digits mixed in)
            if not any(c.isdigit() for c in s):
                continue
        results.append(s)

    # Heuristic: strings resembling passwords come first
    # (short, alphanumeric-ish, no spaces, not a common English word ending)
    def score(s: str) -> int:
        bonus = 0
        if s.lower() in q_lower:
            bonus += 10
        if 6 <= len(s) <= 24:
            bonus += 3
        if s.isalnum():
            bonus += 2
        if any(c.isupper() for c in s) and any(c.islower() for c in s):
            bonus += 2
        return bonus

    results.sort(key=score, reverse=True)
    return results[:80]


def build_static_context(binary_path: str, question: str = "") -> str:
    """
    Fallback context builder using LIEF + raw string extraction.
    Returns a compact, filtered context (≤ 2000 chars) suitable for LLM injection.
    """
    from aira.static_analysis import extract_strings, get_basic_info

    parts: list[str] = []

    try:
        info = get_basic_info(binary_path)
        parts.append(
            f"Format: {info.format} | Arch: {info.architecture} | "
            f"Imagebase: {info.imagebase_hex} | EP: {info.entrypoint_hex}"
        )
        if info.imports:
            imp_names = [i.get("symbol", "") for i in info.imports if i.get("symbol")]
            relevant = [n for n in imp_names if any(
                kw in n.lower() for kw in ("cmp", "str", "crypt", "hash", "mem", "pass", "auth")
            )]
            if relevant:
                parts.append("Relevant imports: " + ", ".join(relevant[:20]))
    except Exception:
        pass

    try:
        raw_strings = extract_strings(binary_path, min_len=4)
        filtered = _filter_strings(raw_strings, question=question)
        if filtered:
            parts.append("Strings extracted from binary:\n" + "\n".join(filtered))
    except Exception:
        pass

    result = "\n\n".join(parts)
    return result[:2000]


# ─── CASCADE HELPERS ────────────────────────────────────────────────────────

_PASSWORD_KW = frozenset([
    "password", "mot de passe", "mdp", "pass", "flag", "serial",
    "key", "crack", "bypass", "auth", "credential", "secret", "code",
    "keygen", "license", "unlock",
])

_FAIL_STR    = ["incorrect", "wrong password", "bad password", "invalid password",
                "denied", "try again", "failed", "wrong!", "bad!"]
_SUCCESS_STR = ["correct password", "access granted", "congratulation", "flag{",
                "well done", "right password", "valid password", "enter to exit",
                "bravo", "success", "correct!"]

_GENERIC_WORDS = frozenset([
    "correct", "wrong", "enter", "please", "error", "password", "welcome",
    "invalid", "access", "denied", "success", "false", "true", "none",
])


def _is_password_question(question: str) -> bool:
    q = question.lower()
    return any(kw in q for kw in _PASSWORD_KW)


def _password_in_strings(context: str) -> bool:
    """
    Heuristic: did Level 1 find a plausible hardcoded password?
    Candidate: 6-30 chars, alphanumeric, mixed case, not a generic English word.
    """
    for line in context.splitlines():
        s = line.strip()
        if (6 <= len(s) <= 30
                and s.isalnum()
                and any(c.isupper() for c in s)
                and any(c.islower() for c in s)
                and s.lower() not in _GENERIC_WORDS):
            return True
    return False


def _find_string_va(binary_path: str, needle: str) -> int | None:
    """Return the virtual address of a string inside the binary using LIEF sections."""
    try:
        import lief
        bin_obj = lief.parse(binary_path)
        if bin_obj is None:
            return None
        needle_b = needle.encode("ascii")
        imagebase: int = 0
        if hasattr(bin_obj, "optional_header"):
            imagebase = int(getattr(bin_obj.optional_header, "imagebase", 0) or 0)
        elif hasattr(bin_obj, "imagebase"):
            imagebase = int(getattr(bin_obj, "imagebase", 0) or 0)
        for section in bin_obj.sections:
            content = bytes(section.content)
            offset = content.find(needle_b)
            if offset >= 0:
                return imagebase + int(section.virtual_address) + offset
    except Exception:
        pass
    return None


def _ghidra_decompile_check(ghidra: "GhidraClient") -> str:
    """
    Level 2: Ghidra decompilation — polyvalent pour tout binaire.

    Stratégie (ordre de priorité) :
    1. Trouver les fonctions qui référencent des strings success/fail via /list_functions
    2. Essayer des noms communs (main, checkPassword, etc.)
    3. Décompiler toutes les fonctions utilisateur courtes jusqu'à trouver
       la logique de comparaison (strcmp, strncmp, XOR, etc.)
    """
    # Récupérer la liste complète des fonctions avec adresses
    funcs_raw = ghidra.list_functions(limit=500)
    func_lower = {f.strip().split(" at ")[0].lower(): f.strip().split(" at ")[0]
                  for f in funcs_raw}
    func_addr = {}
    for f in funcs_raw:
        parts = f.strip().split(" at ")
        if len(parts) == 2:
            func_addr[parts[0]] = parts[1].strip()

    decompiled_parts = []

    # ── Stratégie 1 : chercher les strings success/fail dans Ghidra
    # et trouver les fonctions proches de ces adresses
    try:
        ghidra_lines = ghidra.list_strings()
        ghidra_map = _parse_ghidra_strings(ghidra_lines)
        ref_addrs = []
        for va, text in ghidra_map.items():
            t = text.lower()
            if any(kw in t for kw in _FAIL_STR + _SUCCESS_STR):
                ref_addrs.append(va)

        # Décompiler les fonctions qui contiennent ces adresses
        for va in ref_addrs[:3]:
            result = ghidra.decompile_at(hex(va))
            if result and result[0] not in ("Function not found", "Decompilation failed"):
                decompiled_parts.append(f"### Decompiled at {hex(va)}\n" + "\n".join(result))
    except Exception:
        pass

    # ── Stratégie 2 : noms communs
    candidates = [
        "main", "checkPassword", "check_password", "validatePassword",
        "verify", "authenticate", "checkInput", "passwordCheck",
        "verifyPassword", "validate", "checkPass", "checkSerial",
        "check_serial", "check_key", "checkKey", "verify_key",
        "xor_encrypt", "xor_decrypt", "encrypt", "decrypt",
        "crack", "license", "serial", "keygen",
    ]
    for name in candidates:
        real_name = func_lower.get(name.lower())
        if real_name:
            lines = ghidra.decompile(real_name)
            if lines and lines[0] not in ("Function not found", "Decompilation failed"):
                decompiled_parts.append(f"### Decompiled: {real_name}\n" + "\n".join(lines))

    if decompiled_parts:
        return "\n\n".join(decompiled_parts[:3])

    # ── Stratégie 3 : parcourir toutes les fonctions utilisateur
    # (courtes, non-bibliothèque) et chercher logique de comparaison
    CMP_KEYWORDS = ["strncmp", "strcmp", "stricmp", "compare", "xor", "^ ", "^=",
                    "password", "serial", "key", "auth", "verify", "check"]
    for func_line in funcs_raw:
        fname = func_line.strip().split(" at ")[0]
        # Ignorer les fonctions de bibliothèque
        if (fname.startswith("_") or fname.startswith("d_") or
                fname.startswith("__") or "mingw" in fname.lower() or
                "matherr" in fname.lower() or len(fname) > 40):
            continue
        lines = ghidra.decompile(fname)
        if not lines or lines[0] in ("Function not found", "Decompilation failed"):
            continue
        code = "\n".join(lines).lower()
        if any(kw in code for kw in CMP_KEYWORDS):
            decompiled_parts.append(f"### Decompiled: {fname}\n" + "\n".join(lines))
            if len(decompiled_parts) >= 3:
                break

    return "\n\n".join(decompiled_parts) if decompiled_parts else ""


def _parse_ghidra_strings(ghidra_lines: list[str]) -> dict[int, str]:
    """
    Parse Ghidra string lines like '140004006: "some text"' into {va: text}.
    """
    import re
    pattern = re.compile(r'^([0-9a-fA-F]+):\s*"(.+)"$')
    result: dict[int, str] = {}
    for line in ghidra_lines:
        m = pattern.match(line.strip())
        if m:
            try:
                result[int(m.group(1), 16)] = m.group(2)
            except ValueError:
                pass
    return result


def _angr_auto_solve(
    binary_path: str,
    symexec_url: str = "http://127.0.0.1:8001",
    ghidra_client: "GhidraClient | None" = None,
) -> str:
    """
    Level 3: Call the angr symexec service to find the password automatically.
    Tries Ghidra string addresses first (more accurate), then falls back to LIEF.
    """
    from aira.static_analysis import extract_strings

    try:
        target_va: int | None = None
        avoid_vas: list[str] = []

        # Try Ghidra strings first — FAIL must be checked before SUCCESS
        # (to avoid "incorrect" matching "correct")
        if ghidra_client and ghidra_client.is_available():
            ghidra_lines = ghidra_client.list_strings()
            ghidra_map = _parse_ghidra_strings(ghidra_lines)
            for va, text in ghidra_map.items():
                t = text.lower()
                if any(kw in t for kw in _FAIL_STR):
                    avoid_vas.append(hex(va))
                elif target_va is None and any(kw in t for kw in _SUCCESS_STR):
                    target_va = va

        # Fallback: scan binary bytes for known strings
        if target_va is None:
            raw_strings = extract_strings(binary_path, min_len=4)
            for s in raw_strings:
                s_lower = s.lower()
                if target_va is None and any(kw in s_lower for kw in _SUCCESS_STR):
                    target_va = _find_string_va(binary_path, s)
                elif any(kw in s_lower for kw in _FAIL_STR):
                    va = _find_string_va(binary_path, s)
                    if va:
                        avoid_vas.append(hex(va))
                if target_va and len(avoid_vas) >= 3:
                    break

        if target_va is None:
            # Last resort: try to find any xref to puts/printf with short strings
            # by scanning the binary for typical crackme output patterns
            import lief
            try:
                binary = lief.parse(binary_path)
                if binary:
                    ep = binary.optional_header.addressof_entrypoint + binary.optional_header.imagebase if hasattr(binary, 'optional_header') else None
                    if ep:
                        target_va = ep
            except Exception:
                pass

        if target_va is None:
            return ""

        resp = requests.post(
            f"{symexec_url.rstrip('/')}/solve",
            json={
                "binary_path": str(binary_path),
                "addr_target": hex(target_va),
                "addr_avoid": avoid_vas,
                "stdin_len": 64,
                "input_mode": "stdin",
                "argv_len": 32,
            },
            timeout=120,
        )
        if resp.ok:
            data = resp.json()
            solution = (
                data.get("solution")
                or data.get("stdin")
                or data.get("input")
                or ""
            )
            if solution:
                return f"angr found password: {solution!r}"
    except Exception:
        pass
    return ""


def cascade_mcp_context(
    binary_path: str,
    question: str = "",
    ghidra_client: "GhidraClient | None" = None,
    symexec_url: str = "http://127.0.0.1:8001",
) -> str:
    """
    3-level cascade to build binary analysis context for the LLM.

    Level 1 — Static (always): string extraction + imports + binary info.
              If a clear password candidate is found, stop here.

    Level 2 — Ghidra (if available): decompile the password-check function.
              Provides actual C pseudocode with the real comparison.

    Level 3 — angr (if symexec service running): symbolic execution.
              Finds the input that reaches the success path automatically.
    """
    results: list[str] = []
    is_pwd = _is_password_question(question)

    # ── Level 1 ──────────────────────────────────────────────────────────────
    level1 = build_static_context(binary_path, question=question)
    if level1:
        results.append(f"[Level 1 — Static Analysis]\n{level1}")

    if not is_pwd or _password_in_strings(level1):
        return "\n\n".join(results)[:3000]

    # ── Level 2 ──────────────────────────────────────────────────────────────
    ghidra_ok = ghidra_client and ghidra_client.is_available()
    if ghidra_ok:
        level2 = _ghidra_decompile_check(ghidra_client)
        if level2:
            results.append(f"[Level 2 — Ghidra Decompilation]\n{level2[:2000]}")
            return "\n\n".join(results)[:5000]
        results.append("[Level 2 — Ghidra] Available but decompilation failed. Trying angr...")
    else:
        results.append(
            "[Level 2 — Ghidra] Not available. "
            "Start Ghidra with the HTTP plugin (port 8080) for decompilation."
        )

    # ── Level 3 ──────────────────────────────────────────────────────────────
    level3 = _angr_auto_solve(
        binary_path,
        symexec_url=symexec_url,
        ghidra_client=ghidra_client if ghidra_ok else None,
    )
    if level3:
        results.append(f"[Level 3 — angr Symbolic Execution]\n{level3}")
    else:
        results.append(
            "[Level 3 — angr] Service unavailable or target address not found.\n"
            "To solve manually: `aira solve <binary> <success_address>`"
        )

    # ── Level 4 — Frida (dynamic, optional) ─────────────────────────────────
    try:
        from aira.frida_client import frida_find_password, is_frida_available
        if is_frida_available():
            level4 = frida_find_password(binary_path)
            if level4:
                results.append(level4)
                return "\n\n".join(results)[:6000]
            results.append("[Level 4 — Frida] Available but no strcmp calls captured.")
        else:
            results.append(
                "[Level 4 — Frida] Not installed. "
                "Run `pip install frida-tools` to enable dynamic analysis."
            )
    except Exception:
        results.append("[Level 4 — Frida] Error during dynamic analysis.")

    # ── Level 5 — x64dbg (breakpoints + log) ─────────────────────────────────
    try:
        from aira.x64dbg_client import x64dbg_find_password
        level5 = x64dbg_find_password(binary_path)
        if level5:
            results.append(level5)
            # Si mode API a trouvé quelque chose, arrêter
            if "Mot de passe probable" in level5:
                return "\n\n".join(results)[:7000]
    except Exception:
        results.append("[Level 5 — x64dbg] Error.")

    results.append(
        "⚠️ CASCADE EXHAUSTED: No password was recovered automatically.\n"
        "DO NOT GUESS. State clearly that the password requires manual analysis."
    )

    return "\n\n".join(results)[:7000]
