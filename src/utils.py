import urllib.parse
import hashlib
from fastapi import Request

def canonicalize_payload(raw_text: str) -> str:
    """Recursively decodes URL encoding to prevent evasion tactics."""
    decoded = urllib.parse.unquote(raw_text)
    if decoded != raw_text:
        return canonicalize_payload(decoded)
    return decoded

def generate_request_signature(request: Request, body: bytes) -> str:
    """Generates a unique SHA-256 hash for exact-match decision caching."""
    # We hash the HTTP elements that determine a payload's maliciousness
    payload_string = f"{request.method}|{request.url.path}|{request.url.query}|{body.decode('utf-8', 'ignore')}"
    return hashlib.sha256(payload_string.encode('utf-8')).hexdigest()