# Trepan V5.0 - High Fidelity Risk Markers (Tuned for Victory Lap V5.3.4)

TRIGGERS = {
    # High-Signal Logic Chains
    "SESSION_PROMOTION": [r'sessionId', r'session_id\(', r'session_decode\(', r'session_start\(', r'session_regenerate_id\(', r'RelayState'],
    "XML_INJECTION": [r']]>', r'sprintf\(.*]]>', r'<!\[CDATA\[.*\]\]>', r'SimpleXMLElement', r'xml_parse\('],
    "SSRF_SINK": [r'curl_exec\(', r'file_get_contents\(', r'fsockopen\(', r'pfsockopen\(', r'stream_context_create\('],
    "NGINX_AUTH_BYPASS": [r'set \$panAuthCheck [\'"]off[\'"]', r'auth_request off', r'proxy_pass.*unauth', r'typesAvailableToEveryone'],
    "FILE_WRITE_RCE_SINK": [r'file_put_contents\(', r'fwrite\(', r'fputs\(', r'SaveToFile\(', r'fopen\(.*,.*[\'"]+[wa]'],
    
    # Advanced Sink & Source Analysis (Victory Lap V5.4)
    "TAINTED_SOURCES": [r'window\.location', r'localStorage', r'fetch\(', r'activeSeedPair', r'futureSeedPair', r'addEventListener.*New Client Seed'],
    "DANGEROUS_SINKS": [r'Math\.random', r'getRandomValues', r'HMAC', r'changeSeedPair'],
    "LOGIC_VULNS": [r'nextBetNonce', r'nonce\s*=\s*1', r'if\s*\(.*-', r'if\s*\(.*\|', r'if\s*\(.*_'],
    "SANITIZATION": [r'\.replace\(', r'encodeURIComponent', r'DOMPurify', r'escape'],

    # Structural Anomalies (Chaos Mode)
    "IDENTITY_DRIFT": [r'X-User-Id', r'X-Tenant-ID', r'Authorization', r'jwt\.decode', r'request\.headers', r'user_id\s*='],
    "SHADOW_ROUTE": [r'^v1/', r'^old/', r'^legacy/', r'setup/', r'internal/', r'admin/'],
    
    # Broad/Noisy - Disabled for Full Repo Victory Lap
    # "HTTP_CLIENTS": [r'requests\.(get|post|request)', ...],
    # "SQL_DB": [r'execute\(.*SELECT', ...],
    # "OS_SHELL": [r'os\.system\(', ...],
    # "FILE_IO": [r'open\([\s*[\'"]', ...],
    # "WEB_HANDLERS": [r'CONTENT_LENGTH', r'QUERY_STRING', r'\$_REQUEST', r'\$_SERVER\[[\'"]HTTP_', r'extract\(\$_GET\)', r'<script', r'<\?php'],
}

# Tiered Extension Support (V5.0)
LOGIC_EXTS = {'.py', '.js', '.ts', '.tsx', '.jsx', '.go', '.rb', '.php', '.cpp', '.h', '.cc', '.lua', '.sql', '.tcl', '.sh', '.bat', '.cmd', '.ps1', '.cgi', '.html'}
DATA_EXTS = {'.xml', '.json', '.config', '.ejs', '.jade', '.xaml', '.conf'}
ALLOWED_EXTS = LOGIC_EXTS | DATA_EXTS

IGNORE_DIRS = {'.git', 'node_modules', 'vendor', 'tests', 'Feature', 'venv', '.venv', 'dist', 'build', '__pycache__', '.pytest_cache', '.next', 'out', 'views', 'images', 'js', 'css', 'assets', 'fonts'}