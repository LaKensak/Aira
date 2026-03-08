# AIRA

Toolkit de reverse engineering assisté par IA. Analyse statique, exécution symbolique (angr), instrumentation dynamique (Frida), décompilation (Ghidra via MCP), le tout câblé à des LLMs (OpenAI, Azure, Anthropic, LangFlow).

Ça tourne en CLI, en API FastAPI, ou via MCP pour brancher ça dans LangFlow / Claude Desktop / Cline.

---

## Stack

- **Python 3.11** (3.12 marche avec le `sitecustomize.py` fourni, mais bon)
- **FastAPI + Uvicorn** — backend API + frontend statique
- **LIEF** — parsing PE / ELF / MachO
- **angr** — exécution symbolique, résolution de contraintes
- **Frida** — hooking dynamique, bypass anti-debug
- **YARA** — 14 fichiers de signatures (anti-debug, packers, shellcode, C2, ransomware...)
- **Ghidra + GhidraMCP** — décompilation via bridge MCP
- **MCP (Model Context Protocol)** — exposition d'outils pour agents LLM
- **Capstone** — désassemblage
- **Rich** — affichage CLI

---

## Setup

```bash
# créer le venv
python3.11 -m venv .venv

# activer
source .venv/bin/activate      # Linux/macOS
.\.venv\Scripts\Activate.ps1   # Windows PowerShell

pip install -r requirements.txt
```

Copier `.env.example` → `.env` et remplir les clés API selon ce qu'on utilise.

---

## Architecture

```
.
├── aira/                     # CLI principal
│   ├── cli.py                # point d'entrée, 14 sous-commandes
│   ├── mcp_server.py         # serveur MCP unifié (19 tools)
│   ├── agent.py              # agent Python (pipeline Level 1-4)
│   ├── config.py             # config (.env, chemins absolus)
│   ├── static_analysis.py    # parsing binaire (LIEF)
│   ├── static_detection.py   # scan YARA
│   ├── deep_analysis.py      # analyse complète (entropy, hashes, packer, strings...)
│   ├── ghidra/
│   │   ├── client.py         # client REST → plugin Ghidra
│   │   └── mcp.py            # bridge MCP Ghidra
│   ├── symexec/
│   │   └── client.py         # client → service angr
│   ├── ai/
│   │   ├── client.py         # client LLM générique
│   │   └── langflow_client.py
│   ├── analyzers/            # 13 modules d'analyse spécialisés
│   │   ├── entropy.py
│   │   ├── packer.py
│   │   ├── shellcode_detect.py
│   │   ├── c2_detect.py
│   │   ├── pe_anomalies.py
│   │   ├── war_analyzer.py   # audit sécurité de fichiers WAR Java
│   │   └── ...
│   ├── dynamic/
│   │   ├── frida_manager.py
│   │   └── scripts/          # hooks JS pour Frida
│   └── scripts/              # scripts Ghidra Python (find_main, crack_password...)
│
├── app/
│   ├── main.py               # FastAPI — 10 endpoints
│   ├── backend/
│   │   ├── config.py         # Pydantic Settings
│   │   ├── analysis.py       # fonctions d'analyse côté API
│   │   ├── schemas.py        # modèles Pydantic
│   │   └── services/         # clients OpenAI, Azure, LangFlow
│   └── frontend/             # HTML/JS/CSS (thème sombre, upload, chat, onglets résultats)
│
├── services/
│   ├── ai_service/
│   │   ├── server.py         # FastAPI port 8002
│   │   └── providers/        # OpenAI, Azure, LangFlow, Anthropic, ClaudeCode
│   └── symexec_service/
│       ├── server.py         # FastAPI port 8001
│       └── solver.py         # logique angr
│
├── external/GhidraMCP/       # sous-module — plugin Java + bridge Python
├── signatures/               # 14 fichiers YARA
├── tests/                    # ~14 fichiers de tests unitaires
├── data/                     # uploads + état MCP persisté
├── output/                   # résultats CLI
└── run_mcp_stdio.py          # wrapper MCP stdio pour LangFlow
```

---

## Lancer le bazar

### 1. Backend + Frontend web

```bash
run-services.ps1
```

Interface sur `http://127.0.0.1:8000/`. Upload de binaire, analyse, chat avec LLM, tout est là.

### 2. Services (optionnel mais recommandé)

```bash
# les deux
python services/ai_service/server.py &
python -m services.symexec_service.server &

# ou sous Windows
.\run-services.ps1           # tout
.\run-services.ps1 -AI       # juste le service IA
.\run-services.ps1 -Sym      # juste angr
```

### 3. Ghidra MCP

Prérequis : Ghidra ouvert avec le plugin GhidraMCPPlugin actif (port 8080).

```bash
# bridge stdio (pour Claude Desktop, LangFlow)
aira ghidra-mcp

# bridge SSE (pour Cline, 5ire)
aira ghidra-mcp --transport sse --mcp-port 8081
```

### 4. Serveur MCP unifié AIRA

19 tools exposés : static_info, extract_strings, ghidra_decompile, symbolic_solve, analyze_war, etc.

```bash
# stdio (LangFlow subprocess)
python run_mcp_stdio.py

# SSE
aira mcp-server --transport sse --mcp-port 8082
```

L'état du binaire actif est persisté dans `data/.mcp_state.json`.

---

## Commandes CLI

Tout passe par `aira` (alias de `python -m aira.cli`). Résultats dans `output/`.

| Commande | Ce que ça fait |
|----------|----------------|
| `aira static-info <bin>` | Headers, sections, imports, exports → `static_info.json` |
| `aira scan-antidebug <bin>` | Scan YARA anti-debug → `anti_debug_matches.json` |
| `aira solve <bin> <addr>` | Résolution symbolique angr → `solve.json` |
| `aira graph <bin> <addr> [--png]` | CFG dot/png via angr |
| `aira ai-explain --file foo.asm` | Explication IA du code → `ai_explain.txt` |
| `aira attach <pid> <script.js>` | Injection Frida |
| `aira launch-patched <bin>` | Spawn avec hooks anti-debug Frida |
| `aira ai-monitor <pid> <func>` | Monitoring d'appels via Frida |
| `aira find-path-dynamic <bin> <addr>` | Combo dynamique + symbolique |
| `aira analyze-war <fichier.war>` | Audit sécu WAR Java |
| `aira ghidra-mcp` | Lance le bridge MCP Ghidra |
| `aira mcp-server` | Lance le serveur MCP unifié |
| `aira ghidra-flow [bin]` | Chat interactif LangFlow + Ghidra |

---

## API endpoints

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/health` | Sanity check |
| GET | `/api/providers` | Liste des providers LLM dispo |
| POST | `/api/chat` | Chat (session-based, multi-provider) |
| GET | `/api/chat/history/{id}` | Historique d'une session |
| POST | `/api/upload` | Upload binaire (max 50MB) |
| POST | `/api/upload/analyze` | Upload + analyse statique |
| POST | `/api/analyze/static-info` | Analyse statique sur fichier existant |
| POST | `/api/analyze/deep` | Analyse complète (entropy, hashes, packer, YARA, strings, disasm) |
| POST | `/api/analyze/war` | Audit sécurité WAR Java |

Rate limiting actif : 10 req/min chat, 5 req/min upload/analyse.

---

## Signatures YARA

14 fichiers dans `signatures/` :

`anti_debug` · `anti_vm` · `packers` · `crypto_constants` · `injection` · `shellcode` · `c2_patterns` · `hidden_process` · `api_hashing` · `lolbins` · `ransomware` · `credential_dumping` · `lateral_movement` · `java_war`

---

## Config `.env`

```env
LLM_PROVIDER=langflow              # openai | azure | langflow | anthropic
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
AZURE_OPENAI_ENDPOINT=
LANGFLOW_BASE_URL=http://localhost:7860
LANGFLOW_FLOW_ID=
LANGFLOW_API_KEY=
SYMEXEC_URL=http://127.0.0.1:8001
AI_SERVICE_URL=http://127.0.0.1:8002
GHIDRA_SERVER_URL=http://127.0.0.1:8080/
GHIDRA_MCP_TRANSPORT=stdio         # stdio | sse
GHIDRA_MCP_HOST=127.0.0.1
GHIDRA_MCP_PORT=8081
```

---

## Tests

```bash
python -m pytest -v
# ou
python -m unittest discover -v
# ou sous Windows
.\run_tests.ps1
```

---

## Intégration LangFlow

Le serveur MCP expose 19 tools à LangFlow via **stdio** (subprocess). SSE/streamable-http ne marche pas avec LangFlow (AssertionError Starlette côté asyncio — testé, galère, abandonné).

### Problème de chemin avec espaces

Si ton projet est dans un dossier avec des espaces (`C:\Mon Projet\`), LangFlow va splitter le path dans les arguments. Créer une jonction Windows pour contourner :

```powershell
New-Item -ItemType Junction -Path 'C:\aira' -Target 'C:\Mon Projet'
```

### Config LangFlow

**Settings → MCP Servers → ajouter un serveur STDIO :**

| Champ | Valeur |
|-------|--------|
| Command | `C:\aira\.venv\Scripts\python.exe` |
| Arguments | `C:\aira\run_mcp_stdio.py` |

C'est tout. LangFlow spawn le process, communique en JSON-RPC sur stdin/stdout.

### Config Claude Desktop / Cline

Fichier `claude_mcp_config.json` (ou `claude_desktop_config.json`) :

```json
{
  "mcpServers": {
    "aira": {
      "command": "C:\\aira\\.venv\\Scripts\\python.exe",
      "args": ["C:\\aira\\run_mcp_stdio.py"]
    }
  }
}
```

Pour Cline en SSE :
```bash
aira mcp-server --transport sse --port 8082
# puis dans Cline : Remote Servers → http://127.0.0.1:8082/sse
```

### Tools MCP disponibles

Une fois connecté, l'agent LLM a accès à ces tools :

| Tool | Description |
|------|-------------|
| `set_binary(path)` | Sélectionne le binaire à analyser (persisté dans `data/.mcp_state.json`) |
| `get_binary()` | Retourne le binaire actif |
| `static_info(path?)` | Format, arch, imagebase, sections, imports |
| `extract_strings(min_len?, path?)` | Strings filtrées (bruit CRT viré) |
| `full_analysis(path)` | Combo complet : static_info + strings en un appel |
| `ghidra_status()` | Check si Ghidra est dispo (port 8080) |
| `ghidra_list_functions()` | Liste les fonctions user (CRT/MinGW filtré) |
| `ghidra_find_entrypoint()` | Trouve et décompile le vrai `main` (même sans symbole) |
| `ghidra_decompile(name)` | Décompile une fonction par nom |
| `ghidra_decompile_at(addr)` | Décompile à une adresse (ex: `0x140001450`) |
| `ghidra_list_strings()` | Strings extraites par Ghidra |
| `ghidra_list_imports()` | Imports via Ghidra |
| `symbolic_solve(target, avoid?, ...)` | angr : trouve l'input pour atteindre `target` |
| `symbolic_auto_solve(stdin_len?)` | angr auto : devine success/failure tout seul |
| `analyze_war_file(path)` | Audit sécu WAR Java (résumé) |
| `war_detailed_analysis(path)` | Audit WAR complet (JSON détaillé) |

### Exemple concret : flow LangFlow pour cracker un binaire

Le scénario typique dans LangFlow — un Agent node connecté au MCP AIRA :

```
[Agent Node]
  ├── System Prompt: "Tu es un expert reverse engineering. Analyse le binaire
  │    fourni et trouve le mot de passe / flag."
  ├── MCP Server: aira (stdio)
  └── Model: gpt-4o / claude-sonnet
```

L'agent va enchaîner les appels tout seul :

```
1. full_analysis("C:\\samples\\crackme.exe")
   → Format PE, x86_64, imports: printf, scanf, strcmp...
   → Strings: "Enter password:", "Correct!", "Wrong!"

2. ghidra_find_entrypoint()
   → Décompile main(), voit le strcmp avec une variable

3. ghidra_decompile("check_password")
   → Logique de vérification, XOR avec clé, comparaison à 0x401530

4. symbolic_solve(target="0x401530", avoid="0x401540")
   → PASSWORD FOUND: "s3cr3t_fl4g"
```

Résultat : le LLM a trouvé le flag sans intervention humaine. Le tout via MCP.

### Exemple : ghidra-flow en CLI

Même principe mais directement dans le terminal, sans LangFlow :

```bash
aira ghidra-flow crackme.exe \
  --prompt "Trouve le mot de passe de ce crackme" \
  --flow-id "votre-flow-id" \
  --langflow-api-key "votre-clé"
```

Le transcript est sauvegardé dans `output/ghidra_flow_chat.json`.

---

## Workflow type : cracker un crackme

1. `aira static-info crackme.exe` — voir les imports, strings, sections
2. Ouvrir dans Ghidra, activer le plugin MCP
3. `aira ghidra-flow crackme.exe` — chat interactif, le LLM a accès à la décompilation
4. Identifier la fonction de vérification (xrefs sur les strings "password", "correct"...)
5. `aira solve crackme.exe 0x401234 --avoid 0x401250` — angr trouve l'input
6. Profit

---

## Notes

- `httpx` est pin `<0.28` pour compatibilité avec `openai==1.51.2`
- Python 3.12 : le `sitecustomize.py` à la racine patche `distutils`. Préférer 3.11.
- Graphviz system package nécessaire pour `aira graph --png`
- Frida : vérifier que les versions `frida` / `frida-tools` matchent

---

## Liens

- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
- [Model Context Protocol](https://github.com/modelcontextprotocol)
- [angr](https://docs.angr.io/)
- [Frida](https://frida.re/)
- [LIEF](https://lief-project.github.io/)
