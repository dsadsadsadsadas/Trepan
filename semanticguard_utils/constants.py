import os
from pathlib import Path

# 🛡️ AUDIT_STORAGE_PATH (Neutral Buffer)
# This is the "Stateless Handoff" point where the Hunter drops findings
# and the Server picks them up.
AUDIT_STORAGE_PATH = os.environ.get("SG_AUDIT_PATH", "threat_intel/audits")

def get_audits_dir(root: str = ".") -> Path:
    """Returns the absolute path to the audits directory."""
    return Path(root) / AUDIT_STORAGE_PATH
