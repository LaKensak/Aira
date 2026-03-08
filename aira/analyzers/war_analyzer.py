"""
Analyseur de fichiers WAR (Web Application Archive) — sécurité Java.

Extrait la structure, détecte les vulnérabilités connues, analyse les classes Java,
scan les configurations, et identifie les webshells / backdoors.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import struct
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Patterns de détection Java dangereux ─────────────────────────────────────

# APIs Java à haut risque (exécution de code, deserialization, JNDI, etc.)
DANGEROUS_JAVA_APIS: dict[str, dict[str, str]] = {
    # Exécution de commande
    "Runtime.getRuntime": {"category": "rce", "risk": "critical", "desc": "Exécution de commande système"},
    "Runtime.exec": {"category": "rce", "risk": "critical", "desc": "Exécution de commande système"},
    "ProcessBuilder": {"category": "rce", "risk": "critical", "desc": "Construction de processus externe"},
    "ProcessImpl": {"category": "rce", "risk": "critical", "desc": "Implémentation interne Process"},
    # Deserialization
    "ObjectInputStream": {"category": "deserialization", "risk": "critical", "desc": "Deserialization Java (RCE potentiel)"},
    "readObject": {"category": "deserialization", "risk": "critical", "desc": "Lecture d'objet sérialisé"},
    "readUnshared": {"category": "deserialization", "risk": "critical", "desc": "Lecture d'objet sérialisé (unshared)"},
    "XMLDecoder": {"category": "deserialization", "risk": "critical", "desc": "XMLDecoder (RCE via XML)"},
    "XStream": {"category": "deserialization", "risk": "high", "desc": "XStream deserialization"},
    "Yaml.load": {"category": "deserialization", "risk": "high", "desc": "SnakeYAML unsafe load"},
    # JNDI Injection (Log4Shell, etc.)
    "InitialContext": {"category": "jndi", "risk": "critical", "desc": "Contexte JNDI (injection possible)"},
    "Context.lookup": {"category": "jndi", "risk": "critical", "desc": "JNDI lookup (Log4Shell vector)"},
    "JndiLookup": {"category": "jndi", "risk": "critical", "desc": "JNDI Lookup class"},
    "ldap://": {"category": "jndi", "risk": "critical", "desc": "URL LDAP (JNDI injection)"},
    "rmi://": {"category": "jndi", "risk": "critical", "desc": "URL RMI (JNDI injection)"},
    # Reflection
    "Class.forName": {"category": "reflection", "risk": "high", "desc": "Chargement dynamique de classe"},
    "Method.invoke": {"category": "reflection", "risk": "high", "desc": "Invocation par reflection"},
    "ClassLoader": {"category": "reflection", "risk": "high", "desc": "Chargement dynamique de classes"},
    "defineClass": {"category": "reflection", "risk": "critical", "desc": "Définition dynamique de classe (webshell)"},
    "Unsafe.": {"category": "reflection", "risk": "critical", "desc": "sun.misc.Unsafe (bypass sécurité)"},
    # Fichiers
    "FileOutputStream": {"category": "file_write", "risk": "medium", "desc": "Écriture fichier"},
    "FileWriter": {"category": "file_write", "risk": "medium", "desc": "Écriture fichier texte"},
    "RandomAccessFile": {"category": "file_write", "risk": "medium", "desc": "Accès fichier aléatoire"},
    "Files.write": {"category": "file_write", "risk": "medium", "desc": "NIO écriture fichier"},
    # Réseau
    "ServerSocket": {"category": "network", "risk": "high", "desc": "Écoute réseau (bind)"},
    "Socket(": {"category": "network", "risk": "medium", "desc": "Connexion réseau sortante"},
    "URLConnection": {"category": "network", "risk": "medium", "desc": "Connexion HTTP/URL"},
    "HttpClient": {"category": "network", "risk": "medium", "desc": "Client HTTP"},
    # SQL Injection
    "Statement.execute": {"category": "sqli", "risk": "high", "desc": "Exécution SQL directe (injection possible)"},
    "createStatement": {"category": "sqli", "risk": "high", "desc": "Statement SQL non paramétré"},
    "executeQuery": {"category": "sqli", "risk": "medium", "desc": "Requête SQL (vérifier paramétrage)"},
    # XXE
    "DocumentBuilder": {"category": "xxe", "risk": "high", "desc": "Parsing XML (XXE possible)"},
    "SAXParser": {"category": "xxe", "risk": "high", "desc": "SAX Parser (XXE possible)"},
    "XMLReader": {"category": "xxe", "risk": "high", "desc": "XMLReader (XXE possible)"},
    "TransformerFactory": {"category": "xxe", "risk": "high", "desc": "XSLT Transform (XXE/RCE)"},
    # Expression Language / Template Injection
    "ScriptEngine": {"category": "template_injection", "risk": "critical", "desc": "Moteur de script (RCE)"},
    "eval(": {"category": "template_injection", "risk": "critical", "desc": "Évaluation dynamique de code"},
    "ELProcessor": {"category": "template_injection", "risk": "high", "desc": "Expression Language injection"},
    "SpEL": {"category": "template_injection", "risk": "high", "desc": "Spring Expression Language"},
    # Crypto faible
    "DES": {"category": "weak_crypto", "risk": "medium", "desc": "Chiffrement DES obsolète"},
    "MD5": {"category": "weak_crypto", "risk": "medium", "desc": "Hash MD5 obsolète"},
    "SHA-1": {"category": "weak_crypto", "risk": "low", "desc": "Hash SHA-1 déprécié"},
    "ECB": {"category": "weak_crypto", "risk": "medium", "desc": "Mode ECB (pas de diffusion)"},
}

# Patterns de webshells Java connus
WEBSHELL_PATTERNS: list[dict[str, str]] = [
    {"pattern": r"cmd\.exe|/bin/sh|/bin/bash", "desc": "Shell command in JSP/class", "risk": "critical"},
    {"pattern": r"request\.getParameter.*Runtime", "desc": "JSP command injection pattern", "risk": "critical"},
    {"pattern": r"<%.*Runtime\.getRuntime.*exec.*%>", "desc": "JSP webshell classic", "risk": "critical"},
    {"pattern": r"defineClass.*getParameter", "desc": "ClassLoader webshell", "risk": "critical"},
    {"pattern": r"ProcessBuilder.*getParameter", "desc": "ProcessBuilder webshell", "risk": "critical"},
    {"pattern": r"getRuntime\(\)\.exec\(", "desc": "Runtime.exec() direct call", "risk": "critical"},
    {"pattern": r"Thread\.currentThread\(\)\.getContextClassLoader", "desc": "Context ClassLoader manipulation", "risk": "high"},
    {"pattern": r"base64.*decode.*exec", "desc": "Base64 decode + exec (obfuscated webshell)", "risk": "critical"},
    {"pattern": r"Cipher\.getInstance.*getParameter", "desc": "Encrypted webshell communication", "risk": "critical"},
    {"pattern": r"\.getClass\(\)\.getMethod\(", "desc": "Reflection-based webshell", "risk": "high"},
    {"pattern": r"java\.lang\.reflect\.Proxy", "desc": "Proxy-based code execution", "risk": "high"},
    {"pattern": r"javax\.script\.ScriptEngineManager", "desc": "Script engine webshell", "risk": "critical"},
    {"pattern": r"bcel.*createClass|com\.sun\.org\.apache\.bcel", "desc": "BCEL classloader exploit", "risk": "critical"},
    {"pattern": r"ysoserial|CommonsCollections|Gadget", "desc": "Deserialization gadget chain", "risk": "critical"},
    {"pattern": r"JMXBean|MBeanServer", "desc": "JMX backdoor", "risk": "high"},
    {"pattern": r"behinder|godzilla|antsword|chopper", "desc": "Known webshell tool signature", "risk": "critical"},
]

# Bibliothèques avec CVEs critiques connues
VULNERABLE_LIBS: dict[str, dict[str, str]] = {
    "log4j-core-2.0": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.1": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.2": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.3": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.4": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.5": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.6": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.7": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.8": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.9": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.10": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.11": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.12": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.13": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "log4j-core-2.14": {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "risk": "critical"},
    "commons-collections-3.": {"cve": "CVE-2015-7501", "desc": "Apache Commons Collections deserialization RCE", "risk": "critical"},
    "commons-collections4-4.0": {"cve": "CVE-2015-7501", "desc": "Apache Commons Collections4 deserialization", "risk": "critical"},
    "commons-beanutils-1.": {"cve": "CVE-2019-10086", "desc": "BeanUtils property injection", "risk": "high"},
    "commons-fileupload-1.": {"cve": "CVE-2016-1000031", "desc": "Commons FileUpload deserialization RCE", "risk": "critical"},
    "spring-core-5.": {"cve": "CVE-2022-22965", "desc": "Spring4Shell RCE", "risk": "critical"},
    "spring-core-4.": {"cve": "CVE-2022-22965", "desc": "Spring4Shell RCE (4.x)", "risk": "critical"},
    "spring-beans-5.": {"cve": "CVE-2022-22965", "desc": "Spring4Shell via spring-beans", "risk": "critical"},
    "struts2-core-2.": {"cve": "CVE-2017-5638", "desc": "Apache Struts2 RCE", "risk": "critical"},
    "struts-core-1.": {"cve": "CVE-2014-0114", "desc": "Struts 1.x ClassLoader manipulation", "risk": "critical"},
    "fastjson-1.2.": {"cve": "CVE-2017-18349", "desc": "Fastjson deserialization RCE", "risk": "critical"},
    "jackson-databind-2.": {"cve": "CVE-2019-12384", "desc": "Jackson polymorphic deserialization", "risk": "high"},
    "xstream-1.4.": {"cve": "CVE-2021-39149", "desc": "XStream deserialization RCE", "risk": "critical"},
    "shiro-core-1.": {"cve": "CVE-2016-4437", "desc": "Apache Shiro RememberMe deserialization", "risk": "critical"},
    "velocity-1.": {"cve": "CVE-2020-13936", "desc": "Apache Velocity template injection", "risk": "high"},
    "freemarker-2.3.": {"cve": "CVE-2015-7940", "desc": "FreeMarker template injection", "risk": "high"},
    "hibernate-core-5.": {"cve": "CVE-2020-25638", "desc": "Hibernate SQL injection", "risk": "high"},
    "c3p0-0.9.": {"cve": "CVE-2019-5427", "desc": "C3P0 deserialization RCE", "risk": "critical"},
    "mysql-connector-java-5.": {"cve": "CVE-2021-2471", "desc": "MySQL Connector deserialization", "risk": "high"},
    "mysql-connector-java-8.0.": {"cve": "CVE-2021-2471", "desc": "MySQL Connector SSRF", "risk": "high"},
    "h2-1.": {"cve": "CVE-2021-42392", "desc": "H2 Database JNDI RCE", "risk": "critical"},
    "tomcat-embed-core-8.": {"cve": "CVE-2020-1938", "desc": "Ghostcat AJP", "risk": "critical"},
    "tomcat-embed-core-9.": {"cve": "CVE-2020-1938", "desc": "Ghostcat AJP (9.x)", "risk": "high"},
}

# Patterns de secrets / credentials
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)password\s*[=:]\s*[\"']?[\w@#$%^&*!]+", "Mot de passe hardcodé"),
    (r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*[\"']?[\w\-]+", "Clé API hardcodée"),
    (r"(?i)(?:secret[_-]?key|secretkey)\s*[=:]\s*[\"']?[\w\-]+", "Clé secrète hardcodée"),
    (r"(?i)(?:aws[_-]?access|AKIA)[A-Z0-9]{16,}", "AWS Access Key"),
    (r"(?i)jdbc:[a-z]+://[^\s\"']+", "Chaîne de connexion JDBC"),
    (r"(?i)(?:BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)", "Clé privée RSA/PEM"),
    (r"(?i)bearer\s+[a-zA-Z0-9\-_.~+/]+", "Bearer token"),
    (r"(?i)(?:mysql|postgres|oracle|sqlserver)://\w+:\w+@", "URL de base de données avec credentials"),
    (r"(?i)(?:smtp|imap|pop3)://\w+:\w+@", "Credentials email"),
]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _extract_strings_from_bytes(data: bytes, min_len: int = 4) -> list[str]:
    """Extrait les chaînes ASCII et UTF-8 imprimables."""
    results: list[str] = []
    current: list[str] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


def _is_java_class(data: bytes) -> bool:
    """Vérifie le magic number Java class file (0xCAFEBABE)."""
    return len(data) >= 4 and data[:4] == b"\xca\xfe\xba\xbe"


def _parse_class_info(data: bytes) -> dict[str, Any]:
    """Extraction basique d'informations d'un fichier .class (constant pool strings)."""
    info: dict[str, Any] = {
        "is_valid": False,
        "strings": [],
        "class_refs": [],
        "version": "",
    }
    if not _is_java_class(data) or len(data) < 10:
        return info

    info["is_valid"] = True

    # Version
    try:
        minor = struct.unpack(">H", data[4:6])[0]
        major = struct.unpack(">H", data[6:8])[0]
        version_map = {
            52: "Java 8", 53: "Java 9", 54: "Java 10", 55: "Java 11",
            56: "Java 12", 57: "Java 13", 58: "Java 14", 59: "Java 15",
            60: "Java 16", 61: "Java 17", 62: "Java 18", 63: "Java 19",
            64: "Java 20", 65: "Java 21",
        }
        info["version"] = version_map.get(major, f"class v{major}.{minor}")
    except Exception:
        pass

    # Extraire les strings du constant pool (approche simplifiée)
    info["strings"] = _extract_strings_from_bytes(data, min_len=5)

    return info


@dataclass
class WarAnalysisResult:
    """Résultat complet de l'analyse WAR."""
    path: str
    filename: str
    is_valid_war: bool = False
    size_bytes: int = 0
    md5: str = ""
    sha256: str = ""
    file_entropy: float = 0.0

    # Structure
    total_files: int = 0
    structure: dict[str, list[str]] = field(default_factory=dict)
    java_classes: list[dict[str, Any]] = field(default_factory=list)
    jsp_files: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    lib_jars: list[str] = field(default_factory=list)
    static_files: list[str] = field(default_factory=list)

    # Configuration
    web_xml: dict[str, Any] = field(default_factory=dict)
    manifest: dict[str, str] = field(default_factory=dict)

    # Sécurité
    dangerous_apis: list[dict[str, Any]] = field(default_factory=list)
    webshell_indicators: list[dict[str, Any]] = field(default_factory=list)
    vulnerable_libs: list[dict[str, Any]] = field(default_factory=list)
    secrets_found: list[dict[str, str]] = field(default_factory=list)
    security_misconfigs: list[dict[str, str]] = field(default_factory=list)

    # Entropie par fichier (les plus suspects)
    high_entropy_files: list[dict[str, Any]] = field(default_factory=list)

    # Strings intéressantes
    interesting_strings: list[str] = field(default_factory=list)

    # Score de risque
    risk_score: int = 0
    risk_level: str = "AUCUN"
    verdict: str = ""
    findings_summary: list[str] = field(default_factory=list)


def _analyze_web_xml(content: str) -> dict[str, Any]:
    """Parse web.xml et extrait les informations de sécurité."""
    result: dict[str, Any] = {
        "servlets": [],
        "filters": [],
        "listeners": [],
        "security_constraints": [],
        "error_pages": [],
        "session_config": {},
        "context_params": [],
        "issues": [],
    }

    try:
        # Nettoyer les namespaces pour simplifier le parsing
        content_clean = re.sub(r'\sxmlns(?::\w+)?="[^"]*"', "", content, count=10)
        root = ET.fromstring(content_clean)
    except ET.ParseError:
        result["issues"].append("web.xml parse error — fichier malformé ou obfusqué")
        return result

    # Servlets
    for servlet in root.iter("servlet"):
        name = (servlet.findtext("servlet-name") or "").strip()
        cls = (servlet.findtext("servlet-class") or "").strip()
        if name or cls:
            result["servlets"].append({"name": name, "class": cls})

    # Servlet mappings
    mappings: dict[str, list[str]] = {}
    for mapping in root.iter("servlet-mapping"):
        name = (mapping.findtext("servlet-name") or "").strip()
        pattern = (mapping.findtext("url-pattern") or "").strip()
        if name:
            mappings.setdefault(name, []).append(pattern)
    for s in result["servlets"]:
        s["url_patterns"] = mappings.get(s["name"], [])

    # Filters
    for filt in root.iter("filter"):
        name = (filt.findtext("filter-name") or "").strip()
        cls = (filt.findtext("filter-class") or "").strip()
        if name or cls:
            result["filters"].append({"name": name, "class": cls})

    # Listeners
    for listener in root.iter("listener"):
        cls = (listener.findtext("listener-class") or "").strip()
        if cls:
            result["listeners"].append(cls)

    # Security constraints
    for constraint in root.iter("security-constraint"):
        sc: dict[str, Any] = {"web_resources": [], "auth_constraint": None}
        for wrc in constraint.iter("web-resource-collection"):
            urls = [u.text for u in wrc.iter("url-pattern") if u.text]
            methods = [m.text for m in wrc.iter("http-method") if m.text]
            sc["web_resources"].append({"urls": urls, "methods": methods})
        auth = constraint.find("auth-constraint")
        if auth is not None:
            roles = [r.text for r in auth.iter("role-name") if r.text]
            sc["auth_constraint"] = roles
        result["security_constraints"].append(sc)

    # Session config
    session_cfg = root.find("session-config")
    if session_cfg is not None:
        timeout = session_cfg.findtext("session-timeout")
        if timeout:
            result["session_config"]["timeout_minutes"] = timeout
        cookie_cfg = session_cfg.find("cookie-config")
        if cookie_cfg is not None:
            result["session_config"]["http_only"] = cookie_cfg.findtext("http-only") == "true"
            result["session_config"]["secure"] = cookie_cfg.findtext("secure") == "true"

    # Error pages
    for ep in root.iter("error-page"):
        code = ep.findtext("error-code") or ep.findtext("exception-type") or "?"
        location = ep.findtext("location") or "?"
        result["error_pages"].append({"code": code, "location": location})

    # Context params
    for cp in root.iter("context-param"):
        name = (cp.findtext("param-name") or "").strip()
        value = (cp.findtext("param-value") or "").strip()
        if name:
            result["context_params"].append({"name": name, "value": value[:200]})

    # ── Détection de problèmes de sécurité ──
    # Pas de security constraints
    if not result["security_constraints"]:
        result["issues"].append("Aucune security-constraint définie — toutes les URLs sont publiques")

    # Session sans HttpOnly/Secure
    sc_cfg = result["session_config"]
    if sc_cfg and not sc_cfg.get("http_only"):
        result["issues"].append("Cookie de session sans flag HttpOnly")
    if sc_cfg and not sc_cfg.get("secure"):
        result["issues"].append("Cookie de session sans flag Secure")

    # Servlets suspects
    for s in result["servlets"]:
        cls = s.get("class", "").lower()
        if any(kw in cls for kw in ("invoke", "proxy", "gateway", "debug", "admin", "shell", "exec")):
            result["issues"].append(f"Servlet suspect : {s['name']} → {s['class']}")
        if "/*" in s.get("url_patterns", []):
            result["issues"].append(f"Servlet {s['name']} mappé sur /* (catch-all)")

    # Pas d'error pages personnalisées
    if not result["error_pages"]:
        result["issues"].append("Pas d'error-page configuré — stack traces Java exposées par défaut")

    # Listing directory
    for cp in result["context_params"]:
        if "listing" in cp["name"].lower() and cp["value"].lower() == "true":
            result["issues"].append("Directory listing activé (listings=true)")

    return result


def _analyze_manifest(content: str) -> dict[str, str]:
    """Parse META-INF/MANIFEST.MF."""
    result: dict[str, str] = {}
    for line in content.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
    return result


def _check_vulnerable_libs(jar_name: str) -> dict[str, str] | None:
    """Vérifie si un JAR correspond à une bibliothèque vulnérable connue."""
    jar_lower = jar_name.lower()
    for pattern, info in VULNERABLE_LIBS.items():
        if pattern.lower() in jar_lower:
            return {"jar": jar_name, **info}
    return None


def _scan_for_dangerous_apis(strings: list[str], source: str) -> list[dict[str, Any]]:
    """Scan les strings pour les APIs Java dangereuses."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for s in strings:
        for api, info in DANGEROUS_JAVA_APIS.items():
            if api in s and api not in seen:
                seen.add(api)
                findings.append({
                    "api": api,
                    "source": source,
                    "category": info["category"],
                    "risk": info["risk"],
                    "description": info["desc"],
                    "context": s[:150],
                })
    return findings


def _scan_for_webshells(content: str, source: str) -> list[dict[str, Any]]:
    """Scan le contenu pour des patterns de webshell."""
    findings: list[dict[str, Any]] = []
    for wp in WEBSHELL_PATTERNS:
        matches = re.findall(wp["pattern"], content, re.IGNORECASE)
        if matches:
            findings.append({
                "pattern": wp["desc"],
                "risk": wp["risk"],
                "source": source,
                "matches": [m[:100] if isinstance(m, str) else str(m)[:100] for m in matches[:3]],
            })
    return findings


def _scan_for_secrets(content: str, source: str) -> list[dict[str, str]]:
    """Scan le contenu pour des secrets hardcodés."""
    findings: list[dict[str, str]] = []
    for pattern, desc in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            findings.append({
                "type": desc,
                "source": source,
                "value": m.group()[:80] + ("..." if len(m.group()) > 80 else ""),
            })
    return findings


def analyze_war(war_path: str) -> dict[str, Any]:
    """
    Analyse complète d'un fichier WAR.

    Retourne un dict structuré avec :
    - Structure du WAR (fichiers, classes, JSPs, JARs)
    - Analyse de web.xml et configurations
    - Détection d'APIs dangereuses
    - Détection de webshells
    - Scan de bibliothèques vulnérables
    - Recherche de secrets hardcodés
    - Analyse d'entropie
    - Score de risque global
    """
    path = Path(war_path)
    if not path.exists():
        return {"error": f"File not found: {war_path}"}

    data = path.read_bytes()
    result = WarAnalysisResult(
        path=str(path),
        filename=path.name,
        size_bytes=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        file_entropy=_shannon_entropy(data),
    )

    # Vérifier que c'est un ZIP valide
    if not zipfile.is_zipfile(str(path)):
        return {
            "error": "Not a valid ZIP/WAR file",
            "path": str(path),
            "md5": result.md5,
            "sha256": result.sha256,
        }

    result.is_valid_war = True
    risk_points = 0

    try:
        with zipfile.ZipFile(str(path), "r") as zf:
            namelist = zf.namelist()
            result.total_files = len(namelist)

            # ── 1. Classifier les fichiers ──
            for name in namelist:
                ext = Path(name).suffix.lower()
                if name.endswith(".class"):
                    result.java_classes.append({"path": name, "size": zf.getinfo(name).file_size})
                elif ext in (".jsp", ".jspx", ".jspf"):
                    result.jsp_files.append(name)
                elif name.startswith("WEB-INF/lib/") and ext == ".jar":
                    result.lib_jars.append(Path(name).name)
                elif name in ("WEB-INF/web.xml", "META-INF/MANIFEST.MF") or ext in (".xml", ".properties", ".yml", ".yaml", ".json", ".cfg", ".ini"):
                    result.config_files.append(name)
                elif ext in (".html", ".htm", ".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico"):
                    result.static_files.append(name)

            # Structure résumée
            result.structure = {
                "classes": [c["path"] for c in result.java_classes[:50]],
                "jsps": result.jsp_files[:30],
                "jars": result.lib_jars[:50],
                "configs": result.config_files[:30],
                "static": result.static_files[:20],
            }

            # ── 2. Analyser web.xml ──
            if "WEB-INF/web.xml" in namelist:
                try:
                    web_xml_content = zf.read("WEB-INF/web.xml").decode("utf-8", errors="replace")
                    result.web_xml = _analyze_web_xml(web_xml_content)
                    # Secrets dans web.xml
                    result.secrets_found.extend(_scan_for_secrets(web_xml_content, "WEB-INF/web.xml"))
                    # Chaque issue web.xml ajoute des points de risque
                    risk_points += len(result.web_xml.get("issues", [])) * 5
                except Exception:
                    result.web_xml = {"error": "Failed to parse web.xml"}
            else:
                result.security_misconfigs.append({
                    "issue": "WEB-INF/web.xml manquant",
                    "detail": "Le descripteur de déploiement est absent — configuration par annotations ou framework",
                })

            # ── 3. Analyser MANIFEST.MF ──
            if "META-INF/MANIFEST.MF" in namelist:
                try:
                    manifest_content = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
                    result.manifest = _analyze_manifest(manifest_content)
                except Exception:
                    pass

            # ── 4. Scanner les bibliothèques vulnérables ──
            for jar in result.lib_jars:
                vuln = _check_vulnerable_libs(jar)
                if vuln:
                    result.vulnerable_libs.append(vuln)
                    risk_w = {"critical": 30, "high": 15, "medium": 8}.get(vuln["risk"], 5)
                    risk_points += risk_w

            # ── 5. Analyser les fichiers .class ──
            classes_to_analyze = result.java_classes[:200]  # Limiter pour la perf
            for cls_info in classes_to_analyze:
                try:
                    cls_data = zf.read(cls_info["path"])
                    parsed = _parse_class_info(cls_data)
                    cls_info["java_version"] = parsed.get("version", "")

                    # Scan APIs dangereuses dans les strings
                    apis = _scan_for_dangerous_apis(parsed["strings"], cls_info["path"])
                    result.dangerous_apis.extend(apis)

                    # Scan webshell dans les strings
                    content_str = " ".join(parsed["strings"])
                    ws = _scan_for_webshells(content_str, cls_info["path"])
                    result.webshell_indicators.extend(ws)

                    # Secrets dans les strings
                    result.secrets_found.extend(_scan_for_secrets(content_str, cls_info["path"]))

                    # Entropie
                    ent = _shannon_entropy(cls_data)
                    if ent >= 7.0:
                        result.high_entropy_files.append({
                            "file": cls_info["path"],
                            "entropy": ent,
                            "size": len(cls_data),
                        })

                    # Strings intéressantes
                    for s in parsed["strings"]:
                        s_lower = s.lower()
                        if any(kw in s_lower for kw in (
                            "password", "secret", "key", "token", "admin",
                            "backdoor", "shell", "exploit", "cmd", "exec",
                            "hack", "root", "inject", "payload",
                        )):
                            if s not in result.interesting_strings:
                                result.interesting_strings.append(s[:200])

                except Exception:
                    continue

            # ── 6. Analyser les JSP ──
            for jsp in result.jsp_files[:100]:
                try:
                    jsp_data = zf.read(jsp).decode("utf-8", errors="replace")

                    # Webshells JSP
                    ws = _scan_for_webshells(jsp_data, jsp)
                    result.webshell_indicators.extend(ws)

                    # APIs dangereuses dans JSP
                    jsp_strings = _extract_strings_from_bytes(jsp_data.encode(), min_len=5)
                    apis = _scan_for_dangerous_apis(jsp_strings, jsp)
                    result.dangerous_apis.extend(apis)

                    # Secrets dans JSP
                    result.secrets_found.extend(_scan_for_secrets(jsp_data, jsp))

                except Exception:
                    continue

            # ── 7. Scanner les fichiers de configuration ──
            for cfg in result.config_files:
                if cfg in ("WEB-INF/web.xml", "META-INF/MANIFEST.MF"):
                    continue
                try:
                    cfg_data = zf.read(cfg).decode("utf-8", errors="replace")
                    result.secrets_found.extend(_scan_for_secrets(cfg_data, cfg))

                    # Vérifications spécifiques
                    if "application.properties" in cfg or "application.yml" in cfg:
                        if "spring.datasource" in cfg_data:
                            for line in cfg_data.splitlines():
                                if "password" in line.lower() and "=" in line:
                                    val = line.split("=", 1)[1].strip()
                                    if val and val not in ("${", "{cipher}", "***", ""):
                                        result.secrets_found.append({
                                            "type": "Spring datasource password",
                                            "source": cfg,
                                            "value": line.strip()[:80],
                                        })
                except Exception:
                    continue

            # ── 8. Entropie des JARs internes ──
            for jar_name in result.lib_jars[:30]:
                jar_path = f"WEB-INF/lib/{jar_name}"
                if jar_path in namelist:
                    try:
                        jar_data = zf.read(jar_path)
                        ent = _shannon_entropy(jar_data)
                        if ent >= 7.5:
                            result.high_entropy_files.append({
                                "file": jar_path,
                                "entropy": ent,
                                "size": len(jar_data),
                            })
                    except Exception:
                        continue

    except zipfile.BadZipFile:
        return {"error": "Corrupt ZIP/WAR file", "path": str(path)}
    except Exception as e:
        return {"error": f"Analysis failed: {e}", "path": str(path)}

    # ── 9. Détection de misconfigurations supplémentaires ──
    # Pas de WEB-INF directory
    has_web_inf = any(n.startswith("WEB-INF/") for n in namelist) if namelist else False
    if not has_web_inf:
        result.security_misconfigs.append({
            "issue": "Pas de répertoire WEB-INF",
            "detail": "WAR sans WEB-INF — structure non standard, possible archive corrompue ou malveillante",
        })
        risk_points += 10

    # JSP dans la racine (accessible directement)
    root_jsps = [j for j in result.jsp_files if "/" not in j]
    if root_jsps:
        result.security_misconfigs.append({
            "issue": f"{len(root_jsps)} JSP(s) à la racine du WAR",
            "detail": f"JSP directement accessibles: {', '.join(root_jsps[:5])}",
        })

    # ── 10. Calcul du score de risque ──
    risk_weights = {"critical": 25, "high": 12, "medium": 5, "low": 2}

    for api in result.dangerous_apis:
        risk_points += risk_weights.get(api["risk"], 3)
    for ws in result.webshell_indicators:
        risk_points += risk_weights.get(ws["risk"], 5) * 2  # Double pour webshells
    for secret in result.secrets_found:
        risk_points += 8
    for misconfig in result.security_misconfigs:
        risk_points += 5
    if result.high_entropy_files:
        risk_points += len(result.high_entropy_files) * 3

    result.risk_score = min(100, risk_points)

    if result.risk_score >= 70:
        result.risk_level = "CRITIQUE"
    elif result.risk_score >= 45:
        result.risk_level = "ÉLEVÉ"
    elif result.risk_score >= 20:
        result.risk_level = "MOYEN"
    elif result.risk_score > 0:
        result.risk_level = "FAIBLE"
    else:
        result.risk_level = "AUCUN"

    # ── 11. Résumé des findings ──
    summary: list[str] = []
    if result.webshell_indicators:
        summary.append(f"{len(result.webshell_indicators)} indicateur(s) de webshell détecté(s)")
    if result.vulnerable_libs:
        summary.append(f"{len(result.vulnerable_libs)} bibliothèque(s) vulnérable(s)")
    if result.dangerous_apis:
        critical_apis = [a for a in result.dangerous_apis if a["risk"] == "critical"]
        if critical_apis:
            summary.append(f"{len(critical_apis)} API(s) Java critique(s)")
    if result.secrets_found:
        summary.append(f"{len(result.secrets_found)} secret(s) / credential(s) exposé(s)")
    if result.security_misconfigs:
        summary.append(f"{len(result.security_misconfigs)} misconfiguration(s)")

    result.findings_summary = summary
    result.verdict = f"Risque {result.risk_level} ({result.risk_score}/100)"
    if summary:
        result.verdict += " — " + "; ".join(summary[:3])

    # Limiter les résultats pour ne pas saturer
    result.dangerous_apis = result.dangerous_apis[:50]
    result.webshell_indicators = result.webshell_indicators[:20]
    result.secrets_found = result.secrets_found[:30]
    result.interesting_strings = result.interesting_strings[:50]
    result.high_entropy_files = result.high_entropy_files[:20]

    # Convertir en dict
    from dataclasses import asdict
    return asdict(result)


def format_war_for_llm(analysis: dict, max_chars: int = 3000) -> str:
    """Formate les résultats WAR en texte compact pour injection LLM."""
    if "error" in analysis:
        return f"[WAR ERROR] {analysis['error']}"

    lines: list[str] = []

    lines.append(f"[WAR] {analysis.get('filename', '?')} — {analysis.get('verdict', '?')}")
    lines.append(f"  Size: {analysis.get('size_bytes', 0)} bytes | "
                 f"SHA256: {analysis.get('sha256', '?')[:16]}... | "
                 f"Entropy: {analysis.get('file_entropy', 0)}")
    lines.append(f"  Files: {analysis.get('total_files', 0)} total | "
                 f"Classes: {len(analysis.get('java_classes', []))} | "
                 f"JSPs: {len(analysis.get('jsp_files', []))} | "
                 f"JARs: {len(analysis.get('lib_jars', []))}")

    # Vulnérabilités
    vulns = analysis.get("vulnerable_libs", [])
    if vulns:
        lines.append(f"[VULNERABLE LIBS] {len(vulns)} détectée(s):")
        for v in vulns[:5]:
            lines.append(f"  • {v['jar']} — {v['cve']}: {v['desc']}")

    # Webshells
    ws = analysis.get("webshell_indicators", [])
    if ws:
        lines.append(f"[WEBSHELL] {len(ws)} indicateur(s):")
        for w in ws[:5]:
            lines.append(f"  • {w['pattern']} dans {w['source']} [{w['risk']}]")

    # APIs dangereuses
    apis = analysis.get("dangerous_apis", [])
    if apis:
        critical = [a for a in apis if a["risk"] == "critical"]
        lines.append(f"[DANGEROUS APIs] {len(apis)} détectée(s) ({len(critical)} critiques):")
        for a in critical[:5]:
            lines.append(f"  • {a['api']} dans {a['source']}: {a['description']}")

    # Secrets
    secrets = analysis.get("secrets_found", [])
    if secrets:
        lines.append(f"[SECRETS] {len(secrets)} trouvé(s):")
        for s in secrets[:3]:
            lines.append(f"  • {s['type']} dans {s['source']}")

    # Misconfigs
    misconfigs = analysis.get("security_misconfigs", [])
    web_issues = analysis.get("web_xml", {}).get("issues", [])
    all_issues = misconfigs + [{"issue": i} for i in web_issues]
    if all_issues:
        lines.append(f"[MISCONFIG] {len(all_issues)} problème(s):")
        for m in all_issues[:5]:
            lines.append(f"  • {m.get('issue', '?')}")

    # Strings intéressantes
    strings = analysis.get("interesting_strings", [])
    if strings:
        lines.append(f"[STRINGS] {len(strings)} intéressante(s): {strings[:5]}")

    full = "\n".join(lines)
    if len(full) > max_chars:
        full = full[:max_chars] + "\n... [tronqué]"
    return full
