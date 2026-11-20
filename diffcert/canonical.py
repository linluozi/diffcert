"""Deterministic canonical serialisation.

The whole point of a differential test is that two implementations must agree
*byte for byte* on the same input.  To compare arbitrary Python objects we
serialise them into a canonical UTF-8 byte string:

* mappings are emitted with sorted keys (so insertion order never matters);
* unknown objects fall back to ``{"__type__": ..., "__repr__": ...}``;
* sets/frozensets are sorted by repr (their iteration order is not stable).

Some values are *legitimately* non-deterministic between two runs (a memory
address, a UUID, an ISO timestamp).  Masking them is a pragmatic default, but
``diffcert`` always *reports how many masks it applied* so a diff can never be
quietly "passed" by over-normalising everything.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

Pattern = Tuple[str, "re.Pattern[str]"]

DEFAULT_PATTERNS: List[Pattern] = [
    ("addr", re.compile(r"0x[0-9a-fA-F]+")),
    (
        "uuid",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
    ),
    (
        "iso_ts",
        re.compile(
            r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
            r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
        ),
    ),
]


def _default(obj: Any) -> Any:
    if isinstance(obj, (set, frozenset)):
        return {"__type__": type(obj).__name__, "__items__": sorted(repr(x) for x in obj)}
    if isinstance(obj, (bytes, bytearray)):
        return {"__type__": type(obj).__name__, "__hex__": bytes(obj).hex()}
    try:
        return {"__type__": type(obj).__name__, "__repr__": repr(obj)}
    except Exception:  # pragma: no cover - pathological repr
        return {"__type__": type(obj).__name__}


def canonical_text(
    obj: Any,
    normalize: bool = True,
    patterns: Optional[List[Pattern]] = None,
) -> Tuple[str, Dict[str, int]]:
    """Return (canonical_text, normalization_counts)."""
    text = json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        default=_default,
        separators=(",", ":"),
    )
    counts: Dict[str, int] = {}
    if normalize:
        for name, pat in (patterns if patterns is not None else DEFAULT_PATTERNS):
            def _sub(_m: "re.Match[str]", _name: str = name) -> str:
                counts[_name] = counts.get(_name, 0) + 1
                return "<%s>" % _name

            text = pat.sub(_sub, text)
    return text, counts


def canonical_bytes(
    obj: Any,
    normalize: bool = True,
    patterns: Optional[List[Pattern]] = None,
) -> Tuple[bytes, Dict[str, int]]:
    """Return (canonical_utf8_bytes, normalization_counts)."""
    text, counts = canonical_text(obj, normalize=normalize, patterns=patterns)
    return text.encode("utf-8"), counts


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
