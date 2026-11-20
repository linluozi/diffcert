"""De-duplicating sample accumulator.

The single most important number a differential test can report is the number
of *distinct* inputs it actually exercised -- not how many times a loop ran.
A generator that reseeds its RNG on every call produces the same sample N times
and exercises exactly one input; this class makes that impossible to hide.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Tuple

from .canonical import canonical_bytes


class SampleSet:
    """Accumulate candidate inputs, de-duplicated by SHA-256 of canonical bytes."""

    def __init__(self, normalize: bool = True) -> None:
        self.normalize = normalize
        self.attempts = 0
        self.unique = 0
        self.normalization_counts: Dict[str, int] = {}
        self._index: Dict[str, int] = {}
        self._order: List[Tuple[str, Any]] = []

    def add(self, obj: Any) -> bool:
        """Add one candidate. Return True iff it is a new (unique) sample."""
        self.attempts += 1
        data, counts = canonical_bytes(obj, normalize=self.normalize)
        for key, value in counts.items():
            self.normalization_counts[key] = self.normalization_counts.get(key, 0) + value
        digest = hashlib.sha256(data).hexdigest()
        if digest in self._index:
            return False
        self._index[digest] = len(self._order)
        self._order.append((digest, obj))
        self.unique += 1
        return True

    @property
    def duplicate_rate(self) -> float:
        if self.attempts == 0:
            return 0.0
        return 1.0 - (self.unique / self.attempts)

    def is_degenerate(self, threshold: float = 0.5) -> bool:
        """True when more than ``threshold`` of attempts were duplicates."""
        return self.attempts > 0 and self.duplicate_rate > threshold

    def digest_of(self, obj: Any) -> str:
        data, _ = canonical_bytes(obj, normalize=self.normalize)
        return hashlib.sha256(data).hexdigest()

    def unique_items(self) -> List[Any]:
        return [obj for _digest, obj in self._order]

    def sample_digests(self) -> List[str]:
        return [digest for digest, _obj in self._order]
