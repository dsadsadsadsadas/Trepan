import indexer
import os
import sys
from pathlib import Path
import subprocess
import tempfile
import argparse
import re
import json
import asyncio
import time
import hashlib
from datetime import datetime
import requests
from dotenv import load_dotenv
import io

# Force UTF-8 encoding for Windows terminals to prevent cp1252 crashes
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Ensure we can import from st and threat_intel modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "threat_intel")))

from st.token_bucket import TokenBucket
from threat_intel.signatures import TRIGGERS, ALLOWED_EXTS, IGNORE_DIRS, LOGIC_EXTS, DATA_EXTS

# ── Load .env from threat_intel folder ──────────────────────────────────────
load_dotenv(dotenv_path=Path(__file__).parent / "threat_intel" / ".env")

# 🛡️ IMPORT CENTRALIZED UTILS (V3.0)
try:
    from semanticguard_utils.hashing import generate_finding_id
    from semanticguard_utils.constants import get_audits_dir
except ImportError:
    # Fallback for standalone terminal execution
    sys.path.append(os.path.abspath(os.path.dirname(__file__)))
    try:
        from semanticguard_utils.hashing import generate_finding_id
        from semanticguard_utils.constants import get_audits_dir
    except ImportError:
        # If utils are totally missing, define minimal fallbacks to keep Hunter independent
        def generate_finding_id(repo, file, line, vtype):
            seed = f"{repo}:{file}:{line}:{vtype}"
            import hashlib
            return hashlib.sha256(seed.encode()).hexdigest()[:12]
        def get_audits_dir(root="."):
            return Path(root) / "threat_intel" / "audits"

# --- UI Controller V2.6 ------------------------------------------------------

class UIController:
    def __init__(self):
        self.phases = {"GEN": 0, "SHRED": 0.25, "AUDIT": 0.50, "JUDGE": 0.75, "DONE": 1.0}
        self.last_percent = 0
        self.current_phase = "GEN"

    def update(self, phase: str, current: int, total: int, detail: str = "", threads: list = None):
        self.current_phase = phase
        phases = {"GEN": 0, "SHRED": 0.20, "AUDIT": 0.40, "JUDGE": 0.60, "STRAT": 0.80, "DONE": 1.0}
        if total <= 0:
            percent = phases.get(phase, 0) * 100
        else:
            phase_offset = phases.get(phase, 0)
            phase_progress = (current / total) * 0.20
            percent = (phase_offset + phase_progress) * 100
        
        percent = min(100.0, max(self.last_percent, percent))
        self.last_percent = percent
        
        bar_width = 25
        filled = int(bar_width * percent / 100)
        bar = "#" * filled + "-" * (bar_width - filled)
        
        # Power Bar with Activity Monitor
        activity = ""
        if threads:
            for i in range(5):
                if i < len(threads) and threads[i]:
                    activity += colored(f"[T{i+1}]", Colors.GREEN)
                else:
                    activity += colored(f"[..]", Colors.DIM)

        sys.stdout.write(f"\r{colored(f'[{phase:5}]', Colors.CYAN)} {activity} [{bar}] {percent:3.0f}% | {detail[:50]:<50}")
        sys.stdout.flush()

    def finish(self, message: str):
        self.update("DONE", 1, 1, "Process Complete")
        print(f"\n{colored(message, Colors.GREEN)}")

# --- ANSI Color Codes --------------------------------------------------------

class Colors:
    HEADER = '\033[95m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def colored(text: str, color: str) -> str:
    return f"{color}{text}{Colors.ENDC}"

# --- Language-Neutral Risk Markers (Generic) ----------------------------------

# Centralized Triggers are now imported from signatures.py

# Centralized Config is now imported from signatures.py

def extract_greedy_blocks(code: str, pattern_list: list, max_slices: int = 15) -> str:
    """Slices code around triggers to save tokens on large files (V5.0 Expansion)."""
    lines = code.splitlines()
    if len(lines) < 150: return code
    trigger_regex = re.compile('|'.join(pattern_list), re.IGNORECASE)
    
    keep_indices = set(range(min(20, len(lines)))) # Header context
    slices_found = 0
    for i, line in enumerate(lines):
        if trigger_regex.search(line):
            start = max(0, i - 40) # Increased to 40 for V5.0
            end = min(len(lines), i + 41)
            keep_indices.update(range(start, end))
            slices_found += 1
            if slices_found >= max_slices:
                break
            
    sliced_code = ""
    last_idx = -1
    for idx in sorted(keep_indices):
        if last_idx != -1 and idx > last_idx + 1:
            sliced_code += "\n... [CODE SLICED] ...\n"
        sliced_code += lines[idx] + "\n"
        last_idx = idx
    return sliced_code

class TaintCache:
    """V5.0 Audit Cache: Speeds up subsequent runs by skipping unchanged files."""
    def __init__(self, cache_file=".trepan_cache.json"):
        self.cache_file = Path(cache_file)
        self.cache = {}
        self.lock = asyncio.Lock()
        if self.cache_file.exists():
            try: self.cache = json.loads(self.cache_file.read_text())
            except: pass
    
    def check(self, content):
        fhash = hashlib.md5(content.encode(errors='ignore')).hexdigest()
        return self.cache.get(fhash)
        
    async def save(self, content, result):
        fhash = hashlib.md5(content.encode(errors='ignore')).hexdigest()
        async with self.lock:
            self.cache[fhash] = result
            try: self.cache_file.write_text(json.dumps(self.cache))
            except: pass

# --- Filter Calibration (Noise Reduction) ------------------------------------
EXCLUDED_FILES = {
    "jquery.min.js", "bootstrap.bundle.min.js", "moment.min.js", 
    "jquery.jqgrid.min.js", "jquery.mask.min.js", "spin.min.js",
    "numeral.min.js", "bootstrap-datetimepicker.min.js",
    "mainControllersFlot.js", "mainControllers_placeholders.js", 
    "mobileController.js", "highcharts.js", "chart.js"
}

EXCLUDED_EXTENSIONS = {".png", ".svg", ".ico", ".css"}

# --- Token Bucket is now imported from st.token_bucket ---

# --- Intel Loader (The Librarian) --------------------------------------------

class IntelLoader:
    _WEB_EXTS = ('.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.rb', '.go')
    _C_EXTS    = ('.c', '.cpp', '.h', '.cc')

    def __init__(self):
        self.intel_dir = Path("threat_intel")
        self.library = {
            "Chaos": [], "API": [], "Cloud": [], "CVE": [], "Logic": [],
            "Auth": [], "CHKP": [],
        }
        self.total_loaded = 0

    def load_intel(self):
        if not self.intel_dir.exists(): return
        for file in self.intel_dir.iterdir():
            if file.is_dir(): continue
            try:
                content = file.read_text(errors='ignore')
                name = file.name.lower()
                recipe = {"name": file.name, "content": content}

                # Priority-ordered categorization
                if any(k in name for k in ["chkp", "24919", "checkpoint"]):
                    self.library["CHKP"].append(recipe)
                elif any(k in name for k in ["ldap", "auth", "mfa", "2fa", "gaia"]):
                    self.library["Auth"].append(recipe)
                elif "chaos" in name or "drift" in name:
                    self.library["Chaos"].append(recipe)
                elif any(k in name for k in ["api", "bola", "idor", "route"]):
                    self.library["API"].append(recipe)
                elif any(k in name for k in ["cloud", "docker", "github", "supply"]):
                    self.library["Cloud"].append(recipe)
                elif "cve-" in name or "cve_" in name:
                    self.library["CVE"].append(recipe)
                else:
                    self.library["Logic"].append(recipe)

                self.total_loaded += 1
            except Exception: pass

    def compile_intel_for_file(self, file_path: str, code: str, profile_mandates: str = "") -> str:
        injected = []
        path = file_path.lower()

        # ── Profile Mandates (Vendor-Specific) ──
        if profile_mandates:
            injected.append(profile_mandates)

        # ── Web-facing files: inject path-traversal intel ──
        if path.endswith(self._WEB_EXTS):
            injected.extend([
                r["content"] for r in self.library["CVE"]
                if "path_traversal" in r["name"].lower()
            ])

        # ── C/C++ files: inject memory-corruption intel ──
        if path.endswith(self._C_EXTS):
            injected.extend([r["content"] for r in self.library["Logic"]
                             if "overflow" in r["name"].lower()])

        # ── Go/Python: inject Chaos & Drift ──
        if path.endswith(('.go', '.py')):
            injected.extend([r["content"] for r in self.library["Chaos"]])

        # ── Auth/LDAP paths ──
        if any(k in path for k in ["auth", "login", "ldap", "session"]):
            injected.extend([r["content"] for r in self.library["Auth"]])

        # ── Infra (Docker/.github) ──
        if "docker" in path or ".github" in path:
            injected.extend([r["content"] for r in self.library["Cloud"]])

        # ── API / route handlers ──
        if any(k in path for k in ["api", "route", "handler", "controller"]):
            injected.extend([r["content"] for r in self.library["API"]])

        if not injected: return ""

        mandate = (
            "\n\n### STRATEGIC SEARCH MANDATES\n" + "\n---\n".join(injected) +
            "\n\nCRITICAL: You MUST use the patterns above as your primary audit criteria. "
            "If a code path matches a pattern in these recipes, it is a CONFIRMED finding. "
            "Do not ignore anomalies even if they look like standard coding practices."
        )
        return mandate

# --- Groq Engine & Adversarial Judge -----------------------------------------

# --- Model Agnostic Client (Neural Link Wrapper) -------------------------------

class ModelClient:
    def __init__(self, api_key: str, model: str, rate_limiter: TokenBucket):
        self.api_key = api_key
        self.model = model
        self.rate_limiter = rate_limiter
        # Provider detection
        if "gpt" in model.lower():
            self.endpoint = "https://api.openai.com/v1/chat/completions"
            self.provider = "openai"
        elif "llama" in model.lower() or "localhost" in model.lower() or "127.0.0.1" in model.lower():
            self.endpoint = "http://localhost:11434/v1/chat/completions"
            self.provider = "local"
        else:
            self.endpoint = "https://api.groq.com/v1/chat/completions"
            self.provider = "groq"

    async def _post(self, system, user, temp=0.0):
        # 2026 Mandate: Calculate cost in tokens if applicable
        tokens = (len(system) + len(user)) // 4 + 1000
        import sys
        import random
        
        if "STRAT-MODE" not in system:
            sys.stdout.write(f"\n{colored('[DEBUG]', Colors.CYAN)} Neural Link payload: {tokens:,} tokens")
            sys.stdout.flush()
            
        await self.rate_limiter.consume_with_wait(tokens)
        
        if "STRAT-MODE" not in system:
            sys.stdout.write(f"\n{colored('[NET]', Colors.YELLOW)}   Dispatching audit to {self.provider.upper()} ({self.model})...")
            sys.stdout.flush()

        # --- Exponential Backoff (V5.1 Resilience) ---
        max_retries = 5
        base_delay = 2
        
        for attempt in range(max_retries):
            try:
                headers = {"Content-Type": "application/json"}
                if self.provider != "local":
                    headers["Authorization"] = f"Bearer {self.api_key}"
                
                payload = {
                    "model": self.model,
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                    "temperature": temp, 
                    "response_format": {"type": "json_object"} if "STRAT-MODE" not in system else None
                }
                
                response = await asyncio.to_thread(requests.post, self.endpoint, headers=headers, json=payload, timeout=60)
                
                # V5.1 Live Feedback Loop: Sync remaining tokens/requests
                await self.rate_limiter.calibrate(response.headers)

                if response.status_code == 200:
                    content = response.json()["choices"][0]["message"]["content"]
                    if "STRAT-MODE" in system: return content
                    
                    try: return json.loads(content)
                    except Exception:
                        match = re.search(r"(\{.*\})", content, re.DOTALL)
                        if match:
                            try: return json.loads(match.group(1))
                            except: pass
                
                elif response.status_code == 429:
                    delay = (base_delay ** attempt) + random.uniform(0, 1)
                    sys.stdout.write(f"\n{colored('[RATE]', Colors.RED)}   429 Detected. Backing off {delay:.1f}s...")
                    sys.stdout.flush()
                    await asyncio.sleep(delay)
                    continue
                
                elif response.status_code >= 500:
                    delay = (base_delay ** attempt) + random.uniform(0, 1)
                    sys.stdout.write(f"\n{colored('[ERROR]', Colors.RED)}  Server Error {response.status_code}. Retrying in {delay:.1f}s...")
                    sys.stdout.flush()
                    await asyncio.sleep(delay)
                    continue
                
                else:
                    return None
                    
            except Exception as e:
                if attempt == max_retries - 1: return None
                await asyncio.sleep(base_delay ** attempt)
        
        return None

    async def audit_file(self, file_name, code, system_prompt):
        numbered = "\n".join([f"{i+1}: {line}" for i, line in enumerate(code.splitlines())])
        result = await self._post(system_prompt, f"Audit this code for zero-days and context drift:\n\n{numbered}")
        if isinstance(result, dict) and result.get("findings"):
            return {"file": file_name, "findings": result["findings"]}
        return None

    async def verify_finding(self, finding, code, global_ctx):
        # Default to high-efficiency model for verification
        model_to_use = "gpt-4o-mini"
        system_prompt = (
            "ROLE: Adversarial Judge. MANDATE: Prove if a finding is exploitable.\n"
            "CROSS-FILE CONTEXT MAPPING:\n"
            "If the provided context shows ALL call sites pass static/hardcoded arguments, you MUST debunk the finding as 'STATIC PAYLOAD'.\n"
            "Respond in JSON: {\"status\": \"CONFIRMED|DEBUNKED\", \"adversarial_path\": \"Reasoning (1 sentence)\", \"manual_trace_required\": true|false}"
        )
        user_prompt = f"TARGET FINDING: {json.dumps(finding)}\n\nCODE:\n{code}"
        result = await self._post(system_prompt, user_prompt, temp=0.0)
        if result:
            finding.update(result)
        return finding

# --- Phase 5: The Bounty Reporter --------------------------------------------

class BountyReporter:
    def __init__(self, repo_url):
        # Handle both URLs and local paths
        cleaned = repo_url.rstrip('/').rstrip('\\')
        base = os.path.basename(cleaned)
        self.repo_name = base.replace('.git', '') if base else "local_project"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = get_audits_dir() / f"{self.repo_name}_{self.timestamp}"
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, findings, global_map, risk_surface=None, pending_files=None):
        # 1. Generate Walkthrough (Human-Readable)
        walkthrough_path = self.report_dir / "audit_walkthrough.md"
        with open(walkthrough_path, 'w', encoding='utf-8') as f:
            f.write(f"# Audit Walkthrough: {self.repo_name}\n\n")
            f.write(f"**Timestamp:** {self.timestamp}\n\n")
            
            if pending_files:
                f.write("> [!WARNING]\n")
                f.write("> **TIMEOUT FALLBACK ACTIVATED:** This audit was forcibly terminated due to a 5-minute stall. Results below are partial.\n\n")

            f.write("## 🏛️ Context Drift Analysis\n")
            f.write(f"- **Shadow Routes:** {len(global_map.get('drift_report', {}).get('legacy_paths', []))} legacy prefixes found.\n")
            f.write(f"- **Identity Bearers:** {len(global_map.get('drift_report', {}).get('identity_bearers', []))} functions manually extracting identity headers.\n\n")
            
            f.write("## 🚨 Verified Findings\n")
            full_findings = []
            for target in findings:
                for find in target['findings']:
                    status = find.get('status', 'PENDING')
                    if status == 'CONFIRMED':
                        severity = find.get('severity', 'HIGH').upper()
                        vulnerability = find.get('vulnerability', 'Logic Anomaly')
                        f.write(f"### Target: `{target['file']}`\n")
                        f.write(f"#### [{severity}] {vulnerability}\n")
                        f.write(f"- **Adversarial Path:** {find.get('adversarial_path', 'No path articulated.')}\n\n")
                        
                        # Generate Stable ID for User Zone
                        fid = generate_finding_id(self.repo_name, target['file'], find.get('line', 0), vulnerability)
                        
                        # Determine manual trace guidance
                        trace_vars = find.get('trace_variables') or []
                        if not trace_vars:
                            snippet = (find.get('code_snippet') or '') + ' ' + (find.get('adversarial_path') or '')
                            trace_vars = []
                            # heuristic: extract res.locals.<var>
                            m = re.findall(r"res\.locals\.([A-Za-z0-9_]+)", snippet)
                            trace_vars.extend(m)
                            # webhookSecret or token-like names
                            if 'webhookSecret' in snippet and 'webhookSecret' not in trace_vars:
                                trace_vars.append('webhookSecret')
                            if 'installationId' in snippet and 'installationId' not in trace_vars:
                                trace_vars.append('installationId')
                            if 'tenant_id' in snippet and 'tenant_id' not in trace_vars:
                                trace_vars.append('tenant_id')

                        manual_required = bool(trace_vars) or True

                        full_findings.append({
                            "id": fid,
                            "file": target['file'],
                            "line": find.get('line', 0),
                            "severity": severity,
                            "vulnerability_type": vulnerability,
                            "description": find.get('adversarial_path', 'No description provided.'),
                            "code_snippet": find.get('code_snippet', ''),
                            "manual_trace_required": manual_required,
                            "trace_variables": trace_vars
                        })

            if pending_files:
                f.write("\n## ⏳ Unaudited Files (Timeout Fallback)\n")
                f.write("The following files were identified as high-risk but were NOT audited due to the timeout:\n")
                for pf in pending_files:
                    f.write(f"- `{pf}`\n")
                f.write("\n")

        # 2. Generate JSON (Machine-Readable Handoff)
        json_path = self.report_dir / "full_findings.json"
        handoff_data = {
            "metadata": {
                "repo": self.repo_name,
                "timestamp": self.timestamp
            },
            "findings": full_findings
        }
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(handoff_data, f, indent=2)

        return self.report_dir

# --- Logic Core --------------------------------------------------------------

class RepoFetcher:
    @staticmethod
    def fetch(url, target_dir):
        print(f"{colored('[FETCH]', Colors.CYAN)}   Cloning repository: {url}")
        try:
            subprocess.run(["git", "clone", "--depth", "1", url, target_dir], check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"{colored('[ERROR]', Colors.RED)}   Failed to clone repository: {url}")
            if e.stderr:
                print(f"{colored('[GIT]', Colors.YELLOW)}     {e.stderr.strip()}")
            else:
                print(f"{colored('[GIT]', Colors.YELLOW)}     Error code {e.returncode} (No stderr output)")
            print(f"{colored('[TIP]', Colors.GREEN)}     Check if the URL is correct or if you need authentication.")
            sys.exit(1)
        except FileNotFoundError:
            print(f"{colored('[ERROR]', Colors.RED)}   'git' command not found. Please install git and add it to your PATH.")
            sys.exit(1)

class ASTShredder:
    def __init__(self, path, callback=None):
        self.path = Path(path)
        self.risk_surface = []
        self.global_index = {} # V5.0 Performance Fix: Map basename -> [full_paths]
        self.callback = callback or (lambda p, c, t, d: None)
        pattern_list = [p for sublist in TRIGGERS.values() for p in sublist]
        pattern = '|'.join(pattern_list)
        try:
            self.regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            try:
                safe_pattern = '|'.join([re.escape(p) for p in pattern_list])
                self.regex = re.compile(safe_pattern, re.IGNORECASE)
            except re.error:
                self.regex = re.compile(r"a^")
        self.eligible_count = 0
        self.total_files = 0
        self.critical_regex = re.compile(r'os\.system\(|subprocess\.|exec\(|eval\(|spawn\(|child_process|system\(|popen\(|session_id\(', re.IGNORECASE)

    def scan(self):
        total_files = 0
        eligible_files = []
        for root, dirs, files in os.walk(self.path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for file in files:
                fpath = Path(root) / file
                
                # Build Global Index for O(N) lookup
                bname = fpath.name
                if bname not in self.global_index: self.global_index[bname] = []
                self.global_index[bname].append(fpath)

                if fpath.suffix.lower() in ALLOWED_EXTS:
                    if fpath.name in EXCLUDED_FILES or fpath.suffix.lower() in EXCLUDED_EXTENSIONS:
                        continue
                    eligible_files.append(fpath)
                    total_files += 1
        self.total_files = total_files
        self.eligible_count = len(eligible_files)

        for i, fpath in enumerate(eligible_files):
            self.callback("SHRED", i + 1, total_files, f"Analyzing: {fpath.name}")
            try:
                content = fpath.read_text(errors='ignore')
            except Exception: continue

            try:
                ext = fpath.suffix.lower()
                is_data_file = ext in DATA_EXTS
                if is_data_file:
                    if self.critical_regex.search(content):
                        self.risk_surface.append(fpath)
                else:
                    if self.regex.search(content):
                        self.risk_surface.append(fpath)
            except Exception: pass

    def find_backwards_callers(self, target_file: Path):
        """V5.0 Performance fix: Uses global_index for O(N) complexity."""
        target_basename = target_file.name
        brother_refs = []
        if target_file.suffix.lower() not in {'.sh', '.tcl', '.py', '.js', '.ts', '.php'}:
            return []

        # Instead of walking the whole repo again, we just iterate all files
        # and look for the target_basename string. (V5.1 would index contents too, but this fixes the IO stall)
        for bname, paths in self.global_index.items():
            for other_path in paths:
                if other_path == target_file: continue
                if other_path.suffix.lower() not in ALLOWED_EXTS: continue
                
                try:
                    # We still have to read the file to find the line number, 
                    # but we only do this for logic/config files we've already indexed.
                    content = other_path.read_text(errors='ignore')
                    if target_basename in content:
                        for i, line in enumerate(content.splitlines()):
                            if target_basename in line:
                                brother_refs.append((str(other_path), str(other_path.resolve()), i + 1))
                except: pass
        return brother_refs

# --- JS/TS Lightweight AST Tracker (heuristic-based) ---------------------------------
class JSASTTracker:
    """
    Heuristic AST tracker for JavaScript/TypeScript projects.
    - Builds a lightweight symbol map across files (imports/exports, simple aliases)
    - Tracks occurrences of HMAC, timingSafeEqual, jwt.decode/verify, res.locals, webhookSecret
    - Resolves import closures to collect related files for a given file
    Note: This is a heuristic implementation (regex-based) to provide cross-file context
    without requiring heavy native parsers. It prioritizes traceability for Bloodhound.
    """
    def __init__(self, root_path):
        self.root = Path(root_path)
        self.file_info = {}  # path -> info dict

    def build_index(self):
        exts = {'.js', '.ts', '.jsx', '.tsx'}
        for p in self.root.rglob('*'):
            if p.suffix.lower() in exts:
                try:
                    src = p.read_text(errors='ignore')
                except Exception:
                    src = ''
                info = {
                    'hmac': bool(re.search(r'crypto\.createHmac', src)),
                    'timingSafeEqual': bool(re.search(r'timingSafeEqual', src)),
                    'jwt_decode': bool(re.search(r'jwt\.decode', src)),
                    'jwt_verify': bool(re.search(r'jwt\.verify', src)),
                    'res_locals': re.findall(r'res\.locals\.([A-Za-z0-9_]+)', src),
                    'webhookSecret': bool(re.search(r'webhookSecret', src)),
                    'db_usage': bool(re.search(r"\.(query|find|insert|update)\(|\bdb\.|Model\.find", src)),
                    'aliases': {},
                    'imports': [],
                    'exports': [],
                    'is_entry': bool(re.search(r"(\/routes\/|\/webhook|webhook|middleware|index\.|handler)", str(p).lower())),
                }
                # alias detection: const h = crypto.createHmac(...)
                for m in re.finditer(r"const\s+([A-Za-z0-9_]+)\s*=\s*crypto\.createHmac", src):
                    info['aliases'][m.group(1)] = 'hmac'
                # imports: ES module and require
                for m in re.finditer(r"import\s+(?:\{?([^}]+)\}?\s+from\s+)?[\"'](.+?)[\"']", src):
                    names = m.group(1)
                    mod = m.group(2)
                    info['imports'].append({'names': names, 'module': mod})
                for m in re.finditer(r"require\([\'\"](.+?)[\'\"]\)", src):
                    info['imports'].append({'names': None, 'module': m.group(1)})
                # exports (simple)
                for m in re.finditer(r"export\s+(?:const|function|default)\s+([A-Za-z0-9_]+)", src):
                    info['exports'].append(m.group(1))

                self.file_info[str(p)] = info

    def resolve_module_path(self, base_file: str, module_spec: str):
        # Resolve relative module specifiers to file paths if possible
        if module_spec.startswith('.'):
            base_dir = Path(base_file).parent
            candidate = (base_dir / module_spec).with_suffix('')
            # try with common extensions
            for ext in ['.js', '.ts', '.jsx', '.tsx', '/index.js', '/index.ts']:
                p = Path(str(candidate) + ext)
                if p.exists():
                    return str(p)
        return None

    def import_closure(self, file_path: str, depth=3):
        # BFS over imports to collect related files
        seen = set()
        q = [file_path]
        while q and depth >= 0:
            next_q = []
            for f in q:
                if f in seen: continue
                seen.add(f)
                info = self.file_info.get(f, {})
                for imp in info.get('imports', []):
                    mod = imp.get('module')
                    resolved = self.resolve_module_path(f, mod) if mod else None
                    if resolved and resolved not in seen:
                        next_q.append(resolved)
            q = next_q
            depth -= 1
        return list(seen)

    def analyze_finding(self, file_path: str, finding: dict):
        """
        Augment finding with score, trace_files, and resolved trace_variables using heuristics.
        """
        fp = str((self.root / file_path).resolve()) if not os.path.isabs(file_path) else str(Path(file_path).resolve())
        # if absolute path not in index, try relative matches
        if fp not in self.file_info:
            # try matching by suffix name
            matches = [k for k in self.file_info.keys() if k.endswith(file_path)]
            fp = matches[0] if matches else file_path

        closure = self.import_closure(fp)
        # collect flags across closure
        has_hmac = any(self.file_info.get(f, {}).get('hmac') for f in closure)
        has_timing = any(self.file_info.get(f, {}).get('timingSafeEqual') for f in closure)
        has_jwt_decode = any(self.file_info.get(f, {}).get('jwt_decode') for f in closure)
        has_jwt_verify = any(self.file_info.get(f, {}).get('jwt_verify') for f in closure)
        res_locals = []
        db_usage = False
        webhook_files = []
        for f in closure:
            info = self.file_info.get(f, {})
            res_locals.extend(info.get('res_locals', []) or [])
            if info.get('db_usage'): db_usage = True
            if info.get('webhookSecret'): webhook_files.append(f)

        score = 0
        trace_files = []
        # +3 points: HMAC verification fails to check timingSafeEqual
        if has_hmac and not has_timing:
            score += 3
            trace_files.extend([f for f in closure if self.file_info.get(f, {}).get('hmac')])
        # +2 points: jwt.decode without jwt.verify
        if has_jwt_decode and not has_jwt_verify:
            score += 2
            trace_files.extend([f for f in closure if self.file_info.get(f, {}).get('jwt_decode')])
        # +2 points: tenant/installation IDs attached to res.locals and used in DB/handlers
        tenant_hits = [v for v in res_locals if v in ('tenant_id', 'installationId', 'installation_id')]
        if tenant_hits and db_usage:
            score += 2
            trace_files.extend([f for f in closure if self.file_info.get(f, {}).get('res_locals')])
        # +1 point: entry-point or webhook handler
        if any(self.file_info.get(f, {}).get('is_entry') for f in closure):
            score += 1

        # dedupe trace_files
        trace_files = list(dict.fromkeys(trace_files))

        # resolve trace_variables: prefer provided, else heuristics
        trace_vars = finding.get('trace_variables') or []
        if not trace_vars:
            # try res.locals from closure
            trace_vars = tenant_hits or []
            # fallback: webhookSecret
            if not trace_vars and webhook_files:
                trace_vars = ['webhookSecret']

        manual_required = True if score >= 4 or trace_vars else False

        finding['score'] = score
        finding['trace_files'] = trace_files
        finding['trace_variables'] = trace_vars
        finding['manual_trace_required'] = manual_required
        return finding

async def main():
    parser = argparse.ArgumentParser(description="SemanticGuard Black")
    parser.add_argument("-u", "--url", help="Repository URL to clone")
    parser.add_argument("-d", "--path", help="Local directory path to scan")
    parser.add_argument("-k", "--key", help="API Key (overrides environment)")
    parser.add_argument("-p", "--profile", help="Vendor profile to load (e.g., chkp_gateway)")
    parser.add_argument("-s", "--subpath", help="Directory subpath to focus the hunt")
    args = parser.parse_args()
    
    # Load Profile if specified
    profile_mandates = ""
    if args.profile:
        profile_path = Path("threat_intel/profiles") / f"{args.profile}.md"
        if profile_path.exists():
            content = profile_path.read_text(errors='ignore')
            # Extract regex triggers from profile (naive parsing)
            trigger_matches = re.findall(r'### ([A-Z_]+)\n((?:- .+\n?)+)', content)
            for tname, tlines in trigger_matches:
                new_patterns = [line.strip('- ').strip() for line in tlines.splitlines() if line.strip()]
                if tname in TRIGGERS:
                    TRIGGERS[tname].extend(new_patterns)
                else:
                    TRIGGERS[tname] = new_patterns
            
            # Extract mandates (Scent)
            scent_match = re.search(r'## 🛡️ Strategic Mandates \(Scent\)\n(.*?)(?=\n##|$)', content, re.DOTALL)
            if scent_match:
                profile_mandates = scent_match.group(1).strip()
            print(f"{colored('[PROFILE]', Colors.GREEN)}  Loaded vendor profile: {args.profile}")
        else:
            print(f"{colored('[PROFILE]', Colors.YELLOW)}  Profile {args.profile} not found. Using generic engine.")

    if not args.url and not args.path:
        print(colored("[ERR] Provide either a --url to clone or a --path to scan.", Colors.RED))
        sys.exit(1)

    api_key = args.key or os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY")
    if not api_key: print(colored("[ERR] API key missing. Set OPENAI_API_KEY in threat_intel/.env or pass -k", Colors.RED)); sys.exit(1)
    
    # ── Token Bucket Standardization ──────────────────────────────────────────
    print(colored("[*] INITIALIZING TOKEN BUCKET (STATIC BYPASS)...", Colors.CYAN), end="", flush=True)
    # V5.3.2: Bypassing auto_detect to prevent environmental hangs
    limiter = TokenBucket(max_rpm=10000, max_tpm=5000000)
    print(f" {colored('DONE', Colors.GREEN)}")
    print(f"{colored('[RATE]', Colors.DIM)}    Static Limits: {int(limiter.max_tpm):,} TPM | {int(limiter.max_rpm):,} RPM")
    if limiter.max_tpm < 100000:
        print(f"{colored('[WARN]', Colors.YELLOW)}    Free Tier detected. Throttling is ACTIVE to prevent API rejection.")
    
    print(colored("\n     [SG] SEMANTICGUARD BLACK - NEURAL LINK V2.5", Colors.BOLD))
    
    # Init Neural Link
    librarian = IntelLoader()
    librarian.load_intel()
    print(f"{colored('[LINK]', Colors.GREEN)}    Neural Link established. {librarian.total_loaded} Threat Recipes loaded.")
    
    ui = UIController()
    
    # Persistence Update: Use local clones directory if cloning, else use path
    if args.url:
        repo_name = args.url.split('/')[-1].replace('.git', '')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tmp_dir = os.path.abspath(f"threat_intel/clones/{repo_name}_{timestamp}")
        os.makedirs(tmp_dir, exist_ok=True)
        # Process within persistent directory
        RepoFetcher.fetch(args.url, tmp_dir)
    else:
        tmp_dir = os.path.abspath(args.path)
        repo_name = os.path.basename(tmp_dir)
        if not os.path.exists(tmp_dir):
            print(colored(f"[ERR] Path {tmp_dir} does not exist.", Colors.RED))
            sys.exit(1)
        print(f"{colored('[LOCAL]', Colors.GREEN)}   Scanning local directory: {tmp_dir}")
    
    # Apply subpath scoping
    scan_dir = os.path.join(tmp_dir, args.subpath) if args.subpath else tmp_dir

    # --- Run Tainted Secret Sniper in Python mode (fail-closed) against the cloned repo/path
    try:
        scan_path = Path(scan_dir)
        has_py = False
        if scan_path.exists():
            # look for any .py files under the scan dir
            has_py = any(scan_path.rglob('*.py'))

        if not has_py:
            print(colored(f"[HUNTER] SKIP: No Python files under {scan_dir}; skipping Python sniper.", Colors.YELLOW))
        else:
            sniper_cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "tainted_secret_sniper.py"), scan_dir, "python", "1", repo_name]
            print(f"{colored('[HUNTER]', Colors.CYAN)}   Running sniper: {' '.join(sniper_cmd)}")
            subprocess.run(sniper_cmd, check=False)
    except Exception as e:
        print(colored(f"[HUNTER] WARN: sniper run failed: {e}", Colors.YELLOW))
    
    spof_func = "getTeamIdFromToken"
    idx = indexer.ProjectIndexerV2(os.path.abspath(scan_dir), callback=ui.update)
    idx.index(spof_func)
    global_context = idx.get_context_map()
    
    # THE RADAR: Hunter is our wide-angle scanner (Optimized for volume/cost)
    client = ModelClient(api_key, "gpt-4o-mini", limiter)
    
    # V2.8 SPOF Tracer (The Deep Hunt)
    systemic_failure = False
    spof_meta = idx.search_function(spof_func)
    if spof_meta:
        ui.update("SPOF", 1, 1, f"Auditing SPOF: {spof_func}")
        spof_code = (Path(idx.root_path) / spof_meta["path"]).read_text(errors='ignore')
        spof_prompt = (
            "ROLE: Security Architect / SPOF Auditor\n"
            "MANDATE: Audit this centralized identity helper. Check for:\n"
            "1. JWT signature/secret verification?\n"
            "2. Raw header dependencies (X-Team-Id) without DB check?\n"
            "3. Default fallbacks (if !id return 1)?\n"
            "Respond in JSON: {\"verdict\": \"WEAK|STRONG\", \"reasoning\": \"...\"}"
        )
        res = await client._post(spof_prompt, f"SPOF TARGET CODE:\n{spof_code}")
        if res and res.get("verdict") == "WEAK":
            systemic_failure = True
    else:
        # For non-PHP projects (Node/TS), a global autoloaded helper may not exist.
        # Do NOT abort the audit; log a warning and continue.
        print(f"\n{colored(f'[SPOF] WARN: No global helper {spof_func} found; proceeding with standard audit.', Colors.YELLOW)}")

    shredder = ASTShredder(scan_dir, callback=ui.update)
    shredder.scan()
    # Expose shredder statistics
    try:
        print(f"\n{colored('[SHREDDER]', Colors.CYAN)} Scanned {shredder.eligible_count} eligible files (total files walked: {shredder.total_files}). Found {len(shredder.risk_surface)} files matching risk triggers.")
    except Exception:
        print(colored("[SHREDDER] INFO: Unable to read shredder stats.", Colors.YELLOW))

    # Kill-switch if no files matched
    if len(shredder.risk_surface) == 0:
        print(colored("\n[SHREDDER ERROR] 0 files matched the triggers! Halting AI audit phase because there is nothing to send. Check TRIGGERS and ALLOWED_EXTS.", Colors.RED))
        # Exit cleanly to avoid running the AI phase with empty inputs
        sys.exit(1)

    # Build JS/TS cross-file index for traceability (Bloodhound enhancement)
    tracker = JSASTTracker(tmp_dir)
    try:
        tracker.build_index()
    except Exception:
        # non-fatal: proceed without index if building fails
        tracker = None
    
    audit_tasks = []
    total_targets = len(shredder.risk_surface)
    completed_targets = 0
    
    
    # sem = asyncio.Semaphore(2)  # Removed in V5.1 for Global Suite Semaphore(5)
    
    def _trim_global_context(ctx, rel_path, file_code):
        """Reduces token usage by filtering the global map for semantic relevant routes."""
        if not ctx: return {}
        # Extract keywords from the target file to find related endpoints
        keywords = set(re.findall(r'\b\w{4,}\b', file_code.lower()))
        routes = ctx.get("routes", [])
        
        relevant_routes = []
        for r in routes:
            entry = r.get("entry", "").lower()
            if any(kw in entry for kw in keywords):
                relevant_routes.append(r)

        return {
            "drift_report": ctx.get("drift_report", {}),
            "relevant_routes": relevant_routes[:10] # Tighter limit (10 vs 30)
        }

    cache = TaintCache()

    async def audit_with_progress(fpath, sem, threads=None):
        nonlocal completed_targets
        try:
            code = fpath.read_text(errors='ignore')
        except: return None
        
        rel_path = str(fpath.relative_to(tmp_dir))
        
        # ── V5.0 Audit Cache Check ──
        cached_res = cache.check(code)
        if cached_res:
            completed_targets += 1
            ui.update("AUDIT", completed_targets, total_targets, f"[{completed_targets}/{total_targets}] CACHED: {rel_path}", threads=threads)
            return cached_res

        # ── PASS 1: Lazy Sniff & Slice (Cost Optimization) ──
        pattern_list = [p for sublist in TRIGGERS.values() for p in sublist]
        sliced_code = extract_greedy_blocks(code, pattern_list)
        
        # Only trigger expensive backwards-trace for dangerous sinks
        DANGEROUS_SINKS = {r'os\.system', r'subprocess\.', r'exec\(', r'eval\(', r'spawn', r'child_process', r'system\(', r'popen\(', r'session_id\('}
        has_dangerous_sink = any(re.search(p, code, re.IGNORECASE) for p in DANGEROUS_SINKS)
        
        brother_files_context = ""
        if has_dangerous_sink:
            ui.update("AUDIT", completed_targets, total_targets, f"[*] Deep Trace: {rel_path}", threads=threads)
            brother_refs = shredder.find_backwards_callers(fpath)
            if brother_refs:
                brother_msg = "\n[CROSS-FILE CORRELATION (BROTHER LOGIC)]\n"
                brother_msg += "The following files reference or invoke this target. Use them to trace provenance ($@, $1, etc.):\n"
                
                caller_groups = {}
                for bpath, abs_bpath, blnum in brother_refs:
                    if abs_bpath not in caller_groups: caller_groups[abs_bpath] = []
                    caller_groups[abs_bpath].append(blnum)
                
                # LIMIT TO TOP 5 CALLERS TO PREVENT PAYLOAD EXPLOSION (V4.2 FIX)
                for abs_bpath, lnums in list(caller_groups.items())[:5]:
                    b_rel = os.path.relpath(abs_bpath, tmp_dir)
                    try:
                        with open(abs_bpath, "r", encoding="utf-8", errors="ignore") as bf:
                            bf_lines = bf.readlines()
                        brother_msg += f"\n--- CALLER: {b_rel} ---\n"
                        for lnum in sorted(list(set(lnums))):
                            if 1 <= lnum <= len(bf_lines):
                                brother_msg += f"[LINE {lnum}]: {bf_lines[lnum-1].strip()}\n"
                    except: pass
                brother_files_context = brother_msg

        async with sem:
            ui.update("AUDIT", completed_targets, total_targets, f"[{completed_targets+1}/{total_targets}] Auditing: {rel_path}", threads=threads)
            intel_block = librarian.compile_intel_for_file(rel_path, code)
        
        mandate = "CRITICAL: Search for IDENTITY DRIFT and SHADOW ROUTES."
        
        # V5.0 Unauth Context Injection (Lethal Edge)
        if "/unauth/" in rel_path.lower() or "/rest/" in rel_path.lower():
            mandate += "\n[SECURITY ATTENTION] This file belongs to an UNAUTHENTICATED or REST API path. Any unvalidated user input reaching a sink is a CRITICAL finding. Do not accept 'test mode' as an excuse for lack of validation."
        
        if systemic_failure:
            mandate = "[CRITICAL - SYSTEMIC TRUST FAILURE] The project's centralized trust helper is WEAK."
        
        trimmed_ctx = _trim_global_context(global_context, rel_path, code)
        
        system_prompt = (
            f"GLOBAL CONTEXT MAP (TRIMMED):\n{json.dumps(trimmed_ctx)}\n\n"
            f"{brother_files_context}\n"
            f"{intel_block}\n\n"
            f"{mandate}\n\n"
            "ROLE: Zero-Zero Trust Security Auditor. MANDATE: Find where trust is broken.\n"
            "--- MANDATORY ANALYSIS PROTOCOL ---\n"
            "1. TAINT ORIGIN VERIFICATION: Identify the source of $@, $1, or msg. If a 'CALLER' in the correlation section passes a hardcoded string literal, that input is STATIC. "
            "2. CLOSED-WORLD VERDICT: If ALL discovered call sites are static, you MUST conclude the Sink is NOT exploitable. Terminate with: 'VERDICT: FALSE POSITIVE - STATIC PAYLOAD'. "
            "3. GUILTY UNTIL PROVEN SANITIZED: If user data reaches a Sink without regex/allowlist validation in the SAME scope, it is a CRITICAL vulnerability.\n"
            "4. REASONING SCRATCHPAD: Begin with a 'reasoning' block. Explicitly state: 'Call Site Found in [File] Line [X]: [Line Content]' if available.\n"
            "If issues found, respond as JSON: {\"findings\": [{\"reasoning\", \"severity\", \"vulnerability\", \"line\", \"code_snippet\", \"manual_trace_required\", \"trace_variables\"}]}."
        )
        res = await client.audit_file(rel_path, sliced_code, system_prompt)
        
        # Save to Cache
        if res:
            await cache.save(code, res)
            
        completed_targets += 1
        ui.update("AUDIT", completed_targets, total_targets, f"[{completed_targets}/{total_targets}] Audited: {rel_path}", threads=threads)
        return res

    # --- Phase 4 & 5: Audit & Intelligence Gathering ─────────────────────────
    results = []
    shred_goal = None
    pattern_list = [p for sublist in TRIGGERS.values() for p in sublist]
    
    try:
        # Wrap everything in a 5-minute global timeout to prevent infinite stalls
        async def run_audit_suite():
            nonlocal results, shred_goal
            audit_tasks = []
            sem = asyncio.Semaphore(5)  # V5.1 "Firing Squad" Parallelism
            active_threads = [False] * 5
            thread_lock = asyncio.Lock()

            async def audit_and_collect(fpath):
                # Acquire a "Thread ID" for UI display
                tid = -1
                async with thread_lock:
                    for i in range(5):
                        if not active_threads[i]:
                            active_threads[i] = True
                            tid = i
                            break
                
                try:
                    res = await audit_with_progress(fpath, sem, threads=active_threads)
                    if res and isinstance(res, dict):
                        results.append(res)
                    return res
                finally:
                    async with thread_lock:
                        if tid != -1: active_threads[tid] = False

            # V5.2: Bin Packing (Smallest-First Sorting)
            sorted_surface = sorted(list(shredder.risk_surface), key=lambda x: os.path.getsize(x) if os.path.isfile(x) else 0)

            for fpath in sorted_surface:
                audit_tasks.append(audit_and_collect(fpath))
            
            # await all tasks; they will be cancelled by wait_for if timeout hits
            await asyncio.gather(*audit_tasks)
            
            # Phase 5: Goal Architect (The Strategic Mission)
            high_signal = []
            for target in results:
                for find in target["findings"]:
                    if find.get("severity") in ["CRITICAL", "HIGH"]:
                        high_signal.append({"file": target["file"], "vulnerability": find["vulnerability"], "snippet": find.get("code_snippet")})

            if high_signal:
                ui.update("STRAT", 0, 1, "Synthesizing Lethal Shred Goal...")
                strat_prompt = (
                    "ROLE: Lead Exploit Strategist / Goal Architect (STRAT-MODE)\n"
                    "GLOBAL CONTEXT:\n" + json.dumps(global_context, indent=2) + "\n\n"
                    "MISSION: Generate the single most lethal 'Shred Goal' for a deep-tissue manual/AI audit.\n\n"
                    "Respond ONLY with: MISSION: [Specific Goal] | BREAKOUT: [Specific character/logic to test]"
                )
                user_msg = f"HIGH SIGNAL FINDINGS:\n{json.dumps(high_signal, indent=2)}"
                shred_goal = await client._post(strat_prompt, user_msg) or shred_goal

            # JUDGE Phase
            judge_list = []
            for target in results:
                for finding in target["findings"]:
                    try:
                        if tracker:
                            augmented = tracker.analyze_finding(target['file'], finding)
                            finding.update(augmented)
                    except Exception: pass
                    
                    if finding.get('score', 0) >= 4 or finding.get("severity") in ["CRITICAL", "HIGH"]:
                        judge_list.append((target, finding))
            
            total_judgments = len(judge_list)
            for i, (target, finding) in enumerate(judge_list):
                ui.update("JUDGE", i + 1, total_judgments, f"Verifying: {finding.get('vulnerability', 'anomaly')}")
                # BLOAT FIX: Reading full code but SLICING before sending to AI
                full_code = (Path(tmp_dir) / target['file']).read_text(errors='ignore')
                sliced_code = extract_greedy_blocks(full_code, pattern_list)
                trimmed_ctx = _trim_global_context(global_context, target['file'], full_code)
                await client.verify_finding(finding, sliced_code, json.dumps(trimmed_ctx))

        # Victory Lap Patch (V5.3.3): Increasing timeout for full repo scans
        await asyncio.wait_for(run_audit_suite(), timeout=3600)

    except asyncio.TimeoutError:
        print(colored("\n\n[!!!] TIMEOUT REACHED (5 MIN STALL). PERSISTING PARTIAL RESULTS...", Colors.RED))
    except Exception as e:
        print(colored(f"\n[!!!] CRITICAL ERROR IN AUDIT SUITE: {e}", Colors.RED))
    
    # --- Persistence Hand-off ────────────────────────────────────────────────
    audited_files = {r['file'] for r in results}
    pending_files = [f for f in shredder.risk_surface if f not in audited_files]
    
    reporter = BountyReporter(args.url or tmp_dir)
    report_path = reporter.generate(results, global_context, [], pending_files=pending_files)
    
    if shred_goal:
        with open(report_path / "strategic_mission.md", 'w', encoding='utf-8') as sf:
            sf.write(f"# Strategic Mission: {repo_name}\n\nMISSION: {shred_goal}\n")

    ui.finish(f"Audit Complete. Intel Report in {report_path}")
    if shred_goal:
        print(f"\n{colored('🏆 RECOMMENDED SHRED GOAL:', Colors.YELLOW)}\n{shred_goal}\n")

if __name__ == "__main__":
    asyncio.run(main())
