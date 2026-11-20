"""Delta-debugging (ddmin) input minimisation.

Given an input that makes two implementations disagree, shrink it to a minimal
input that *still* makes them disagree, so a bug report contains a repro you can
read instead of a 20 KB blob.  Works on ``str``, ``bytes``, ``list`` and
``tuple`` inputs.  The number of evaluations is capped so shrinking can never
run away on a huge input.
"""

from __future__ import annotations

from typing import Any, Callable, List, Tuple

SequenceLike = (str, bytes, bytearray, list, tuple)


def _to_elements(case: Any) -> List[Any]:
    if not isinstance(case, SequenceLike):
        raise TypeError("ddmin only supports str/bytes/list/tuple inputs, got %r" % type(case))
    return list(case)


def _from_elements(original: Any, elements: List[Any]) -> Any:
    if isinstance(original, str):
        return "".join(elements)
    if isinstance(original, (bytes, bytearray)):
        return bytes(elements)
    if isinstance(original, tuple):
        return tuple(elements)
    return list(elements)


def _split(elements: List[Any], n: int) -> List[List[Any]]:
    size = len(elements)
    if n <= 1 or size == 0:
        return [list(elements)]
    # as-even-as-possible partition into n contiguous chunks
    base, rem = divmod(size, n)
    chunks: List[List[Any]] = []
    start = 0
    for i in range(n):
        length = base + (1 if i < rem else 0)
        if length == 0:
            continue
        chunks.append(elements[start:start + length])
        start += length
    return chunks


def ddmin(case: Any, fails: Callable[[Any], bool], max_evals: int = 400) -> Tuple[Any, int]:
    """Return (minimal_case, evaluations_used).

    ``fails(c)`` must return True when ``c`` still reproduces the disagreement.
    The caller guarantees ``fails(case)`` is True for the starting input.
    """
    elements = _to_elements(case)
    n = 2
    evals = 0

    while len(elements) >= 2:
        chunks = _split(elements, n)
        reduced = False

        # 1) try to keep everything except one chunk
        for idx, _chunk in enumerate(chunks):
            if evals >= max_evals:
                return _from_elements(case, elements), evals
            candidate = chunks[:idx] + chunks[idx + 1:]
            flat = [el for c in candidate for el in c]
            evals += 1
            if fails(_from_elements(case, flat)):
                elements = flat
                n = max(n - 1, 2)
                reduced = True
                break

        # 2) otherwise try a single chunk on its own
        if not reduced:
            for chunk in chunks:
                if evals >= max_evals:
                    return _from_elements(case, elements), evals
                evals += 1
                if fails(_from_elements(case, chunk)):
                    elements = list(chunk)
                    n = 2
                    reduced = True
                    break

        # 3) otherwise increase granularity
        if not reduced:
            if n >= len(elements):
                break
            n = min(len(elements), n * 2)

    return _from_elements(case, elements), evals
