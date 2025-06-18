import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

DEFAULT_HASH_DB_PATH = Path.home() / ".promptfoo" / "modelaudit_hashes.json"


def compute_file_hash(path: str, algorithm: str = "sha256") -> str:
    """Return the hexadecimal digest of a file."""
    hasher = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_hash_db(path: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Load known good/bad hash database."""
    db_path = Path(path) if path else DEFAULT_HASH_DB_PATH
    if not db_path.is_file():
        return {"known_good": {}, "known_bad": {}}
    try:
        data = json.loads(db_path.read_text())
        return {
            "known_good": data.get("known_good", {}),
            "known_bad": data.get("known_bad", {}),
        }
    except Exception:
        return {"known_good": {}, "known_bad": {}}


def check_hash(
    file_hash: str, db: Dict[str, Dict[str, Any]]
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Return hash status (known_good/known_bad) and metadata if present."""
    if file_hash in db.get("known_bad", {}):
        return "known_bad", db["known_bad"][file_hash]
    if file_hash in db.get("known_good", {}):
        return "known_good", db["known_good"][file_hash]
    return None, None
