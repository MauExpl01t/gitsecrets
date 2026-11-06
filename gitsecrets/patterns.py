"""Patrones para detectar secretos en una línea de texto: firmas conocidas
de proveedores (formato fijo, alta confianza) y una detección genérica por
entropía para secretos sin formato reconocible (variable con nombre
sospechoso + valor que parece aleatorio, no un placeholder)."""
from __future__ import annotations

import math
import re
from collections import Counter

KNOWN_PATTERNS = {
    "Clave de AWS": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Clave privada": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "Token de GitHub": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "Token de Slack": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "Clave de API de Google": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "Clave secreta de Stripe": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "Clave de Twilio": re.compile(r"SK[0-9a-fA-F]{32}"),
    "JSON Web Token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}

GENERIC_ASSIGNMENT = re.compile(
    r"""(?i)\b(api[_-]?key|secret|token|passwd|password|pwd|access[_-]?key|auth[_-]?key)"""
    r"""\s*[:=]\s*['"]([^'"]{8,100})['"]""")

PLACEHOLDER_WORDS = {
    "changeme", "change_me", "your_api_key_here", "example", "xxxx", "xxxxxxxx",
    "placeholder", "todo", "fixme", "test", "testing", "dummy", "fake", "sample",
    "insert_key_here", "redacted", "none", "null", "secret", "password", "123456",
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in freq.values())


def looks_random(value: str, min_entropy: float = 3.3) -> bool:
    """Descarta placeholders obvios y valores con muy poca variedad de
    caracteres antes de confiar en el umbral de entropía."""
    if value.lower() in PLACEHOLDER_WORDS:
        return False
    if len(set(value)) < 5:
        return False
    return shannon_entropy(value) >= min_entropy
