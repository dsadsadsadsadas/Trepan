#!/usr/bin/env python3
"""
🛡️  SEMANTICGUARD INDEXER V2.4 — Context Drift & Trust Analysis
Advanced AST + Regex mapping for Versioning Analysis and Identity Drift.
"""

import os
import ast
import json
import argparse
import re
from pathlib import Path
from typing import List, Dict, Set, Optional, Any, Tuple
from collections import Counter, deque

# --- Configuration & Patterns -----------------------------------------------

ROUTE_DECORATORS = {'route', 'get', 'post', 'put', 'delete', 'patch', 'websocket'}
DIRECT_SINKS = {
    'db': ['execute', 'query', 'commit', 'rollback', 'upsert', 'db.', 'Session.', 'sql.', 'Exec('],
    'network': ['requests.', 'httpx.', 'socket.', 'urllib.', 'fetch', 'axios.', 'http.', 'http.Get(', 'http.Post('],
    'file': ['open(', 'os.path.', 'Path.', 'shutil.', 'write(', 'read(', 'fs.', 'os.Open('],
    'process': ['subprocess.', 'os.system', 'exec(', 'eval(', 'spawn', 'exec.', 'exec.Command(']
}
INPUT_SOURCES = {
    'request.args', 'request.json', 'request.form', 'request.headers', 'request.values', 'request.files', 
    'r.FormValue', 'req.body', 'params[', 'X-User-Id', 'X-Tenant-ID', 'Authorization', 'jwt.decode'
}
IDENTITY_HEADERS = {'X-User-Id', 'X-Tenant-ID', 'Authorization', 'jwt.decode', 'r.Header.Get', 'request.headers'}

# --- Regex Visitor (Multilingual + Trust) -----------------------------------

class RegexVisitor:
    def __init__(self, file_path: Path, module_path: str):
        self.file_path = file_path
        self.module_path = module_path
        self.definitions = {}
        self.has_global_middleware = False
        self.identity_drift = False

    def scan(self, content: str, ext: str):
        # 1. Identity & Middleware Checks
        if 'r.Use(' in content or 'app.use(' in content: self.has_global_middleware = True
        if any(h in content for h in IDENTITY_HEADERS): self.identity_drift = True

        # 2. Identify Functions/Definitions
        patterns = {
            '.go': [
                r'func\s+(?:\(.*\)\s+)?(\w+)\s*\(',
                r'\.Get\("([^"]+)"', r'\.Post\("([^"]+)"', r'\.HandleFunc\("([^"]+)"', r'\.Route\("([^"]+)"'
            ],
            '.js': [r'function\s+(\w+)\s*\(', r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\('],
            '.ts': [r'function\s+(\w+)\s*\(', r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\('],
            '.php': [r'function\s+(\w+)\s*\(', r'public\s+function\s+(\w+)\s*\('],
            '.rb': [r'def\s+(\w+)']
        }
        
        matches = []
        for p in patterns.get(ext, []):
            matches.extend(re.findall(p, content))
        
        # 3. Registry Populate
        for func_name in matches:
            if not func_name: continue
            is_route = any(kw in content for kw in ['app.get', 'app.post', 'router.', 'HandleFunc', 'r.Get(', 'r.Post('])
            
            # Simple Path Prefix extraction
            path_prefix = "unknown"
            if is_route:
                path_match = re.search(r'["\'](/[^"\']*)["\']', content)
                if path_match:
                    parts = path_match.group(1).split('/')
                    path_prefix = f"/{parts[1]}" if len(parts) > 1 else "/"

            meta = {
                "name": func_name,
                "module": self.module_path,
                "path": str(self.file_path),
                "line": content.count('\n', 0, content.find(func_name)) + 1,
                "type": "route" if is_route else "function",
                "path_prefix": path_prefix,
                "decorators": [],
                "has_identity_claims": any(h in content for h in IDENTITY_HEADERS),
                "calls": re.findall(r'(\w+)\s*\(', content),
                "inputs": [s for s in INPUT_SOURCES if s in content],
                "direct_sinks": [],
                "reaches_sink": False,
                "risk_score": 0
            }
            for cat, kws in DIRECT_SINKS.items():
                if any(kw in content for kw in kws):
                    meta["direct_sinks"].append(cat)
                    meta["reaches_sink"] = True
            self.definitions[func_name] = meta

# --- AST Visitor V2 (Python + Trust) ----------------------------------------

class V2Visitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, module_path: str):
        self.file_path = file_path
        self.module_path = module_path
        self.definitions = {}
        self.imports = {}
        self.current_function = None

    def visit_FunctionDef(self, node):
        decorators = []
        for dec in node.decorator_list:
            name = self._get_name(dec.func if isinstance(dec, ast.Call) else dec)
            if name: decorators.append(f"@{name}")

        is_route = any(any(rd in d for rd in ROUTE_DECORATORS) for d in decorators)
        
        func_meta = {
            "name": node.name,
            "module": self.module_path,
            "path": str(self.file_path),
            "line": node.lineno,
            "type": "route" if is_route else "function",
            "path_prefix": "/", # Default for Python
            "decorators": decorators,
            "has_identity_claims": False,
            "calls": [],
            "inputs": [],
            "direct_sinks": [],
            "reaches_sink": False,
            "risk_score": 0
        }
        self.current_function = func_meta
        self.generic_visit(node)
        self.definitions[node.name] = func_meta
        self.current_function = None

    def visit_Call(self, node):
        if self.current_function:
            name = self._get_name(node.func)
            if name:
                self.current_function["calls"].append(name)
                if any(h in name for h in IDENTITY_HEADERS): self.current_function["has_identity_claims"] = True
                for cat, kws in DIRECT_SINKS.items():
                    if any(kw in name for kw in kws):
                        self.current_function["direct_sinks"].append(f"{cat}:{name}")
                        self.current_function["reaches_sink"] = True
                if any(src in name for src in INPUT_SOURCES): self.current_function["inputs"].append(name)
        self.generic_visit(node)

    def _get_name(self, node):
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return None

# --- Global Engine V2.4 -----------------------------------------------------

class ProjectIndexerV2:
    def __init__(self, root_path: str, callback=None):
        self.root_path = Path(root_path)
        self.registry = {}
        self.file_visitors = []
        self.callback = callback or (lambda phase, curr, total, detail: None)

    def index(self, spof_target: str = "getTeamIdFromToken"):
        # 1. Speed Guard Configuration
        STRICT_IGNORE_DIRS = {'.git', 'node_modules', 'vendor', 'tests', 'venv', '.venv', 'dist', 'build', '__pycache__', '.pytest_cache', '.next', 'out', 'images', 'js', 'css', 'assets', 'fonts', '3rdParty'}
        MAX_FILE_SIZE = 500 * 1024  # 500KB
        
        # 2. V2.9 Autoload Crawler (The Final Trace)
        self.callback("CRAWL", 0, 1, f"Target: {spof_target} | Searching in root: {self.root_path}")
        priority_files = self._analyze_composer()
        scanned_paths = set()
        
        while priority_files:
            target_path = priority_files.pop()
            if target_path in scanned_paths or not target_path.exists(): continue
            
            self.callback("CRAWL", len(scanned_paths), len(scanned_paths) + len(priority_files) + 1, f"Following: {target_path.name}")
            self._scan_file(target_path, scanned_paths, priority_files, MAX_FILE_SIZE)
            scanned_paths.add(target_path)

        # 3. Pre-scan for Total Count (Y)
        self.callback("GEN", 0, 1, "Pre-scanning directory...")
        total_files = 0
        for root, dirs, files in os.walk(self.root_path):
            # Strict directory pruning during walk
            dirs[:] = [d for d in dirs if d not in STRICT_IGNORE_DIRS]
            total_files += len(files)
        
        # 3. Main Indexing Loop
        files_scanned = 0
        last_top_level = None
        
        for root, dirs, files in os.walk(self.root_path):
            # Strict directory pruning
            dirs[:] = [d for d in dirs if d not in STRICT_IGNORE_DIRS]
            
            rel_root = Path(root).relative_to(self.root_path)
            current_top_level = rel_root.parts[0] if rel_root.parts else None
            
            # Path-Aware Heartbeat (on entering new top-level dir)
            if current_top_level != last_top_level and current_top_level:
                self.callback("GEN", files_scanned, total_files, f"Entering: {current_top_level}")
                last_top_level = current_top_level

            for file in files:
                path = Path(root) / file
                if path in scanned_paths: continue # Skip already crawled
                
                files_scanned += 1
                ext = path.suffix.lower()
                rel_path = path.relative_to(self.root_path)
                module_path = str(rel_path.with_suffix('')).replace(os.sep, '.')
                
                # Periodic Heartbeat
                if files_scanned % 50 == 0 or files_scanned == total_files:
                    self.callback("GEN", files_scanned, total_files, str(rel_path.parent))

                self._scan_file(path, scanned_paths, set(), MAX_FILE_SIZE)

        self._propagate_sinks()
        self._calculate_drift()

    def _scan_file(self, path: Path, scanned_paths: set, priority_queue: set, max_size: int):
        ext = path.suffix.lower()
        rel_path = path.relative_to(self.root_path)
        module_path = str(rel_path.with_suffix('')).replace(os.sep, '.')
        
        try:
            if path.stat().st_size > max_size:
                self.registry[f"{module_path}._OVERSIZED_"] = {
                    "name": path.name, "path": str(rel_path), "type": "oversized_skipped",
                    "risk_score": 0, "direct_sinks": [], "reaches_sink": False,
                    "path_prefix": "skipped", "has_identity_claims": False,
                    "decorators": [], "calls": [], "inputs": []
                }
                return

            if ext not in ['.py', '.go', '.js', '.ts', '.php', '.rb']:
                return

            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                visitor = None
                if ext == '.py':
                    visitor = V2Visitor(rel_path, module_path)
                    visitor.visit(ast.parse(content))
                else:
                    visitor = RegexVisitor(rel_path, module_path)
                    visitor.scan(content, ext)
                
                if visitor:
                    self.file_visitors.append(visitor)
                    for name, meta in visitor.definitions.items():
                        self.registry[f"{module_path}.{name}"] = meta
                    
                    # V2.9 Recursive Follower (PHP)
                    if ext == '.php' and priority_queue is not None:
                        self._follow_php_includes(content, path, priority_queue)
        except Exception:
            pass

    def _analyze_composer(self) -> set:
        composer_path = self.root_path / "composer.json"
        found = set()
        if composer_path.exists():
            try:
                data = json.loads(composer_path.read_text())
                # Follow 'files' autoloading
                autoload = data.get("autoload", {}).get("files", [])
                autoload_dev = data.get("autoload-dev", {}).get("files", [])
                for f in autoload + autoload_dev:
                    target = (self.root_path / f).resolve()
                    if target.exists(): found.add(target)
            except Exception: pass
        return found

    def _follow_php_includes(self, content: str, current_path: Path, queue: set):
        import glob
        # 1. Static Include Resolver
        # Handles: require __DIR__ . '/path' and include(__DIR__ . "/path")
        matches = re.findall(r"(?:require|include)(?:_once)?\s*\(?\s*__DIR__\s*\.\s*['\"](.*?)['\"]\s*\)?", content)
        for m in matches:
            target = (current_path.parent / m.lstrip('/')).resolve()
            if target.exists(): queue.add(target)
        
        # 2. V2.9 Glob-Resolution Logic
        # Handles: glob(__DIR__."/path/*.php") and glob(__DIR__ . '/path/*.php')
        glob_matches = re.findall(r"glob\(\s*__DIR__\s*\.\s*['\"](.*?)['\"]\s*\)", content)
        for g in glob_matches:
            target_pattern = (current_path.parent / g.lstrip('/')).resolve()
            for match in glob.glob(str(target_pattern)):
                queue.add(Path(match))

    def search_function(self, name: str) -> Optional[Dict]:
        for k, v in self.registry.items():
            if k.split('.')[-1] == name:
                return v
        return None

    def _propagate_sinks(self):
        queue = deque([k for k, v in self.registry.items() if v.get("direct_sinks")])
        while queue:
            sink_node = queue.popleft()
            for k, v in self.registry.items():
                if sink_node in v.get("calls", []) and not v.get("reaches_sink", False):
                    v["reaches_sink"] = True
                    queue.append(k)

    def _calculate_drift(self):
        # 1. Versioning Coverage
        prefixes = [v["path_prefix"] for v in self.registry.values() if v["type"] == "route"]
        prefix_stats = Counter(prefixes)
        
        prefix_coverage = {}
        for prefix in prefix_stats:
            routes = [v for v in self.registry.values() if v.get("path_prefix") == prefix and v.get("type") == "route"]
            secure = [r for r in routes if r.get("decorators") or not r.get("reaches_sink", False)]
            prefix_coverage[prefix] = len(secure) / len(routes) if routes else 1.0

        for k, v in self.registry.items():
            if v["type"] == "route":
                coverage = prefix_coverage.get(v["path_prefix"], 1.0)
                if coverage < 0.5: # 50% drift threshold
                    v["risk_score"] += 5
                    v.setdefault("risk_reasons", []).append("STRUCTURAL_DRIFT")

    def get_context_map(self) -> Dict:
        return {
            "routes": [
                {
                    "path": m["path_prefix"], "entry": k, 
                    "trust": "ID_BEARER" if m["has_identity_claims"] else "GENERIC",
                    "sinks": m["direct_sinks"], "risk": m["risk_score"]
                }
                for k, m in self.registry.items() if m["type"] == "route"
            ],
            "drift_report": {
                "identity_bearers": [k for k, v in self.registry.items() if v.get("has_identity_claims")],
                "legacy_paths": [v["path_prefix"] for v in self.registry.values() if v["path_prefix"] in ['/v1', '/old', '/legacy']]
            }
        }

# --- Module ---

def run_scan(path: str, callback=None) -> Dict:
    indexer = ProjectIndexerV2(path, callback)
    indexer.index()
    return indexer.get_context_map()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    print(json.dumps(run_scan(parser.parse_args().path), indent=2))
