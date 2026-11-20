"""Certify that two implementations agree on a de-duplicated set of inputs."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from .canonical import canonical_bytes, sha256_hex
from .ddmin import ddmin
from .sampleset import SampleSet


def _impl_name(fn: Any) -> str:
    name = getattr(fn, "__name__", None)
    if name:
        return name
    return repr(fn)


def _capture(fn: Callable[[Any], Any], case: Any) -> Any:
    """Run fn(case); capture a normal value or an exception in a comparable form."""
    try:
        return ("ok", fn(case))
    except Exception as exc:  # noqa: BLE001 - we compare exception identity on purpose
        return ("exc", type(exc).__name__, str(exc))


def _out_bytes(captured: Any, normalize: bool) -> bytes:
    data, _ = canonical_bytes(captured, normalize=normalize)
    return data


@dataclass
class Mismatch:
    case_repr: str
    case_digest: str
    out_a_sha: str
    out_b_sha: str
    out_a: Any
    out_b: Any
    normalized: Dict[str, int]
    shrunk: bool
    shrink_evals: int
    original_case_repr: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_repr": self.case_repr,
            "case_digest": self.case_digest,
            "out_a_sha256": self.out_a_sha,
            "out_b_sha256": self.out_b_sha,
            "out_a": _display(self.out_a),
            "out_b": _display(self.out_b),
            "normalized": dict(sorted(self.normalized.items())),
            "shrunk": self.shrunk,
            "shrink_evals": self.shrink_evals,
            "original_case_repr": self.original_case_repr,
        }


def _display(captured: Any) -> Any:
    if isinstance(captured, tuple) and captured and captured[0] == "exc":
        return {"raised": captured[1], "message": captured[2]}
    if isinstance(captured, tuple) and len(captured) == 2 and captured[0] == "ok":
        try:
            return {"returned": captured[1]}
        except Exception:  # pragma: no cover
            return {"returned": repr(captured[1])}
    return captured


@dataclass
class Certificate:
    impl_a: str
    impl_b: str
    attempts: int
    unique_inputs: int
    duplicate_rate: float
    degenerate: bool
    degenerate_threshold: float
    normalize: bool
    mismatches: List[Mismatch] = field(default_factory=list)
    normalization_counts: Dict[str, int] = field(default_factory=dict)
    sample_digests: List[str] = field(default_factory=list)
    env: Dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """A certificate passes only if it is non-degenerate AND has zero mismatches."""
        return (not self.degenerate) and len(self.mismatches) == 0

    def digest(self) -> str:
        """Deterministic digest of the evidence (no timestamps, no raw reprs)."""
        payload = {
            "impl_a": self.impl_a,
            "impl_b": self.impl_b,
            "attempts": self.attempts,
            "unique_inputs": self.unique_inputs,
            "normalize": self.normalize,
            "sample_digests": self.sample_digests,
            "mismatches": [
                [m.case_digest, m.out_a_sha, m.out_b_sha] for m in self.mismatches
            ],
        }
        data, _ = canonical_bytes(payload, normalize=False)
        return hashlib.sha256(data).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "impl_a": self.impl_a,
            "impl_b": self.impl_b,
            "attempts": self.attempts,
            "unique_inputs": self.unique_inputs,
            "duplicate_rate": round(self.duplicate_rate, 6),
            "degenerate": self.degenerate,
            "degenerate_threshold": self.degenerate_threshold,
            "normalize": self.normalize,
            "passed": self.passed,
            "mismatch_count": len(self.mismatches),
            "normalization_counts": dict(sorted(self.normalization_counts.items())),
            "certificate_sha256": self.digest(),
            "env": self.env,
            "mismatches": [m.to_dict() for m in self.mismatches],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False)


def certify(
    impl_a: Callable[[Any], Any],
    impl_b: Callable[[Any], Any],
    cases: Iterable[Any],
    *,
    name_a: Optional[str] = None,
    name_b: Optional[str] = None,
    normalize: bool = True,
    shrink: bool = True,
    max_shrink_evals: int = 400,
    degenerate_threshold: float = 0.5,
) -> Certificate:
    """Compare two callables over de-duplicated ``cases`` and build a certificate."""
    sample_set = SampleSet(normalize=normalize)
    mismatches: List[Mismatch] = []
    output_norm_total: Dict[str, int] = {}

    def _add_output_norms(counts: Dict[str, int]) -> None:
        for key, value in counts.items():
            output_norm_total[key] = output_norm_total.get(key, 0) + value

    for case in cases:
        if not sample_set.add(case):
            continue  # duplicate input: already exercised, skip (but still counted as an attempt)

        captured_a = _capture(impl_a, case)
        captured_b = _capture(impl_b, case)
        bytes_a, norm_a = canonical_bytes(captured_a, normalize=normalize)
        bytes_b, norm_b = canonical_bytes(captured_b, normalize=normalize)
        _add_output_norms(norm_a)
        _add_output_norms(norm_b)
        if bytes_a == bytes_b:
            continue

        norm_merged: Dict[str, int] = {}
        for src in (norm_a, norm_b):
            for key, value in src.items():
                norm_merged[key] = norm_merged.get(key, 0) + value

        original_repr = repr(case)
        final_case = case
        shrunk = False
        shrink_evals = 0

        if shrink:
            def fails(candidate: Any) -> bool:
                return _out_bytes(_capture(impl_a, candidate), normalize) != _out_bytes(
                    _capture(impl_b, candidate), normalize
                )

            try:
                reduced, shrink_evals = ddmin(case, fails, max_evals=max_shrink_evals)
                if repr(reduced) != original_repr:
                    shrunk = True
                final_case = reduced
                captured_a = _capture(impl_a, final_case)
                captured_b = _capture(impl_b, final_case)
                bytes_a = _out_bytes(captured_a, normalize)
                bytes_b = _out_bytes(captured_b, normalize)
            except TypeError:
                # non-sequence input: cannot shrink, keep original
                shrunk = False

        mismatches.append(
            Mismatch(
                case_repr=repr(final_case),
                case_digest=sha256_hex(canonical_bytes(final_case, normalize=normalize)[0]),
                out_a_sha=sha256_hex(bytes_a),
                out_b_sha=sha256_hex(bytes_b),
                out_a=captured_a,
                out_b=captured_b,
                normalized=norm_merged,
                shrunk=shrunk,
                shrink_evals=shrink_evals,
                original_case_repr=original_repr,
            )
        )

    env = {
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
    }

    combined_norms: Dict[str, int] = dict(sample_set.normalization_counts)
    for key, value in output_norm_total.items():
        combined_norms[key] = combined_norms.get(key, 0) + value

    return Certificate(
        impl_a=name_a or _impl_name(impl_a),
        impl_b=name_b or _impl_name(impl_b),
        attempts=sample_set.attempts,
        unique_inputs=sample_set.unique,
        duplicate_rate=sample_set.duplicate_rate,
        degenerate=sample_set.is_degenerate(degenerate_threshold),
        degenerate_threshold=degenerate_threshold,
        normalize=normalize,
        mismatches=mismatches,
        normalization_counts=combined_norms,
        sample_digests=sample_set.sample_digests(),
        env=env,
    )
