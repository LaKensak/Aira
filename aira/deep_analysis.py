"""
AIRA Deep Analysis — Orchestrateur d'analyse approfondie.

Combine tous les analyseurs et génère un contexte riche pour le LLM.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from aira.analyzers.entropy            import analyze_entropy
from aira.analyzers.hashes             import compute_hashes
from aira.analyzers.strings_classifier import classify_strings
from aira.analyzers.packer             import detect_packer
from aira.analyzers.api_classifier     import classify_apis
from aira.analyzers.disasm             import disasm_entrypoint
from aira.analyzers.hidden_process     import detect_hidden_process
from aira.analyzers.shellcode_detect   import detect_shellcode
from aira.analyzers.string_obfuscation import detect_string_obfuscation
from aira.analyzers.pe_anomalies       import detect_pe_anomalies
from aira.analyzers.c2_detect          import detect_c2
from aira.analyzers.war_analyzer       import analyze_war, format_war_for_llm


def run_deep_analysis(binary_path: str) -> dict:
    """
    Lance tous les analyseurs sur un binaire et retourne un dict structuré.
    Chaque analyseur est isolé — une erreur n'arrête pas les autres.
    """
    path = Path(binary_path)
    if not path.exists():
        return {"error": f"File not found: {binary_path}"}

    t0 = time.monotonic()
    result: dict = {
        "path":     str(path),
        "filename": path.name,
    }

    def safe(name: str, fn, *args, **kwargs):
        try:
            result[name] = fn(*args, **kwargs)
        except Exception as e:
            result[name] = {"error": str(e)}

    safe("hashes",              compute_hashes,        str(path))
    safe("entropy",             analyze_entropy,       str(path))
    safe("packer",              detect_packer,         str(path))
    safe("strings_classified",  classify_strings,      str(path))
    safe("disasm_ep",           disasm_entrypoint,     str(path))
    safe("hidden_process",      detect_hidden_process, str(path))
    safe("shellcode",           detect_shellcode,      str(path))
    safe("obfuscation",         detect_string_obfuscation, str(path))
    safe("pe_anomalies",        detect_pe_anomalies,   str(path))
    safe("c2",                  detect_c2,             str(path))

    # api_classifier a besoin des imports → on les récupère depuis static_analysis
    try:
        from aira.static_analysis import get_basic_info
        info = get_basic_info(str(path))
        safe("api_behavior", classify_apis, info.imports)
    except Exception as e:
        result["api_behavior"] = {"error": str(e)}

    # YARA multi-règles
    result["yara"] = _run_all_yara(str(path))

    # WAR analysis (si c'est un fichier .war ou .jar)
    if path.suffix.lower() in (".war", ".jar"):
        safe("war_analysis", analyze_war, str(path))

    result["analysis_time_s"] = round(time.monotonic() - t0, 2)
    return result


def _run_all_yara(binary_path: str) -> dict:
    """Lance toutes les règles YARA disponibles et retourne les résultats groupés."""
    from pathlib import Path as _Path
    from aira.static_detection import scan_with_yara

    sig_dir = _Path(__file__).resolve().parent.parent / "signatures"
    rule_files = {
        "anti_debug":         sig_dir / "anti_debug.yar",
        "anti_vm":            sig_dir / "anti_vm.yar",
        "packers":            sig_dir / "packers.yar",
        "crypto_constants":   sig_dir / "crypto_constants.yar",
        "injection":          sig_dir / "injection.yar",
        "shellcode":          sig_dir / "shellcode.yar",
        "c2_patterns":        sig_dir / "c2_patterns.yar",
        "hidden_process":     sig_dir / "hidden_process.yar",
        "api_hashing":        sig_dir / "api_hashing.yar",
        "lolbins":            sig_dir / "lolbins.yar",
        "ransomware":         sig_dir / "ransomware.yar",
        "credential_dumping": sig_dir / "credential_dumping.yar",
        "lateral_movement":   sig_dir / "lateral_movement.yar",
        "java_war":           sig_dir / "java_war.yar",
    }

    yara_results: dict[str, list] = {}
    for category, rules_path in rule_files.items():
        if rules_path.exists():
            try:
                matches = scan_with_yara(binary_path, str(rules_path))
                if matches:
                    yara_results[category] = matches
            except Exception as e:
                yara_results[category] = [{"error": str(e)}]

    total = sum(len(v) for v in yara_results.values() if isinstance(v, list))
    return {
        "matches":     yara_results,
        "total_hits":  total,
        "categories_hit": list(yara_results.keys()),
    }


def format_for_llm(deep: dict, max_chars: int = 3000) -> str:
    """
    Formate les résultats deep analysis en texte compact pour injection LLM.
    Priorise les informations les plus critiques.
    """
    lines: list[str] = []

    # Hashes
    h = deep.get("hashes", {})
    if h and "error" not in h:
        lines.append(f"[HASHES] SHA256={h.get('sha256','?')} MD5={h.get('md5','?')} "
                     f"imphash={h.get('imphash','?')} size={h.get('size_kb','?')}KB")

    # Packer
    p = deep.get("packer", {})
    if p and "error" not in p:
        if p.get("detected"):
            lines.append(f"[PACKER] {p['detected']} (confiance {p.get('confidence',0)}%) "
                         f"— {'; '.join(p.get('indicators', [])[:2])}")
        else:
            lines.append("[PACKER] Aucun packer détecté")

    # Entropy
    ent = deep.get("entropy", {})
    if ent and "error" not in ent:
        verdict = ent.get("overall_verdict", "?")
        suspicious = [s for s in ent.get("sections", []) if s.get("verdict") != "normal"]
        lines.append(f"[ENTROPY] Verdict global: {verdict}"
                     + (f" | Sections suspectes: {[s['name']+':'+str(s['entropy']) for s in suspicious]}"
                        if suspicious else ""))

    # API behavior
    api = deep.get("api_behavior", {})
    if api and "error" not in api:
        lines.append(f"[API RISK] {api.get('summary','?')} (score {api.get('risk_score',0)}/100)")
        for cat_id, cat in api.get("categories", {}).items():
            if cat.get("risk") in ("critical", "high"):
                lines.append(f"  • {cat['label']}: {', '.join(cat['matched'][:6])}")

    # YARA
    yara = deep.get("yara", {})
    if yara and yara.get("total_hits", 0) > 0:
        lines.append(f"[YARA] {yara['total_hits']} correspondance(s) dans: {', '.join(yara.get('categories_hit', []))}")
        for cat, matches in yara.get("matches", {}).items():
            if isinstance(matches, list):
                rules = [m.get("rule", "?") for m in matches if isinstance(m, dict)]
                if rules:
                    lines.append(f"  • {cat}: {', '.join(rules[:5])}")

    # Strings classifiées (uniquement les plus critiques)
    sc = deep.get("strings_classified", {})
    if sc and "error" not in sc:
        for cat in ("flags_ctf", "urls", "domains", "ips", "commands", "interesting_strings"):
            items = sc.get(cat, [])
            if items:
                lines.append(f"[STRINGS/{cat.upper()}] {items[:5]}")

    # Disasm EP (juste les premières instructions)
    dis = deep.get("disasm_ep")
    if dis and "error" not in (dis or {}) and dis and dis.get("instructions"):
        insns = dis["instructions"][:6]
        insn_str = "; ".join(f"{i['mnemonic']} {i['op_str']}" for i in insns)
        lines.append(f"[DISASM EP @ {dis.get('entry_point','?')}] {insn_str}")

    # PE Anomalies
    pea = deep.get("pe_anomalies", {})
    if pea and "error" not in pea and pea.get("score", 0) > 0:
        lines.append(f"[PE ANOMALIES] score={pea['score']}/100 — {pea.get('verdict','?')}")
        for a in pea.get("anomalies", [])[:4]:
            if a.get("severity") in ("critical", "high"):
                lines.append(f"  • {a['type']}: {a.get('detail','')[:80]}")

    # Shellcode
    sc2 = deep.get("shellcode", {})
    if sc2 and "error" not in sc2 and sc2.get("score", 0) > 0:
        lines.append(f"[SHELLCODE] score={sc2['score']}/100 — {sc2.get('verdict','?')}")
        for f in sc2.get("findings", [])[:3]:
            lines.append(f"  • {f['type']}: {f.get('description','')[:80]}")

    # Obfuscation
    ob = deep.get("obfuscation", {})
    if ob and "error" not in ob and ob.get("score", 0) > 0:
        lines.append(f"[OBFUSCATION] score={ob['score']}/100 — {ob.get('verdict','?')}")

    # C2
    c2 = deep.get("c2", {})
    if c2 and "error" not in c2 and c2.get("score", 0) > 0:
        lines.append(f"[C2] score={c2['score']}/100 — {c2.get('verdict','?')}")
        for ind in c2.get("indicators", [])[:3]:
            lines.append(f"  • {ind['type']}: {str(ind.get('value',''))[:60]}")

    # Processus cachés
    hp = deep.get("hidden_process", {})
    if hp and "error" not in hp and hp.get("confidence", 0) > 0:
        lines.append(f"[HIDDEN PROCESS] confiance={hp['confidence']}% — {hp.get('verdict','?')}")

    # WAR analysis
    war = deep.get("war_analysis", {})
    if war and "error" not in war:
        lines.append(format_war_for_llm(war, max_chars=800))

    full = "\n".join(lines)
    if len(full) > max_chars:
        full = full[:max_chars] + "\n... [tronqué]"
    return full
