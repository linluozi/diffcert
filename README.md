# diffcert

**A differential-testing certificate harness: it proves how many *distinct* inputs a test actually exercised, then compares two implementations byte-for-byte and shrinks every mismatch to a minimal repro.**

`diffcert` exists because "I ran 2000 random cases, 0 mismatches" is usually a
lie in disguise. If the generator reseeds its RNG on every call, or the space of
outputs is small, you can loop 2000 times and test the *same input* over and over.
`diffcert` reports `unique_inputs` (SHA-256 de-duplicated) next to `attempts`, so
a degenerate run is impossible to hide — a certificate whose samples are mostly
duplicates is marked `degenerate: true` and **never passes**.

Upstream: none

This is an original project (no upstream code was copied). See `LICENSE`.

## Why this is not another benchmark wrapper

The one number a differential test must publish is the number of **de-duplicated
independent samples**, not loop iterations. `diffcert` makes that number a
first-class, hashed artefact:

- **De-duplicate inputs by content.** Every candidate is serialised to canonical
  UTF-8 (sorted dict keys, stable set ordering) and hashed with SHA-256. Repeats
  are counted as `attempts` but collapse into a single `unique_inputs`.
- **Compare byte-for-byte.** Two implementations agree only if the canonical
  bytes of their return value (or of their raised exception type+message) are
  identical. `True` vs `1`, `"1"` vs `1`, and "raised ValueError" vs "returned
  None" are all mismatches.
- **Account for normalisation.** Legitimately non-deterministic fragments
  (memory addresses `0x…`, UUIDs, ISO timestamps) are masked by default — but
  the certificate always reports *how many masks were applied*, so a diff can
  never be quietly "passed" by over-normalising.
- **Shrink mismatches.** Every disagreement is reduced with delta-debugging
  (ddmin) to a minimal input that still reproduces it.
- **Emit a reproducible certificate.** Certificates carry no wall-clock time; the
  same inputs produce the same `certificate_sha256` on any machine.

## Install

```bash
pip install .        # from this checkout
# or, editable:
pip install -e .
```

No third-party dependencies. Python >= 3.9 (developed and tested on CPython 3.12.3).

## Quick start

```bash
python -m diffcert demo --write results
```

This runs two auditable scenarios:

1. **A degenerate generator** that reseeds `random.Random(4321)` inside the loop
   and yields 2,000 "cases" — `diffcert` proves they are all the same input.
2. **A real disagreement** (`str.upper` vs `str.lower`) shrunk to single-character
   repros.

## Library API

```python
from diffcert import certify

def impl_a(s): ...
def impl_b(s): ...

cert = certify(impl_a, impl_b, cases, name_a="impl_a", name_b="impl_b")
print(cert.attempts, cert.unique_inputs, cert.duplicate_rate)
print(cert.passed)                 # True only if non-degenerate AND zero mismatches
print(cert.to_json())              # deterministic certificate (no timestamps)
print(cert.digest())               # reproducible SHA-256 of the evidence
for m in cert.mismatches:
    print(m.case_repr, m.out_a, m.out_b, m.shrunk, m.shrink_evals)
```

Lower-level pieces are importable too: `SampleSet`, `canonical_bytes`,
`canonical_text`, `ddmin`.

## Evidence (all numbers below are real output of `python -m diffcert demo --write results`)

**Scenario A — degenerate "2000 random cases":**

```
attempts=2000 unique_inputs=1 duplicate_rate=0.9995 degenerate=True passed=False
certificate_sha256=65d1397798c04b10aa9c663630f074ca9a9f3e05d12b60ac148d3959338810b8
```

2,000 loop iterations exercised **1** distinct input. This is the exact
anti-pattern that produces fake "2000 samples, 0 mismatch" claims; `diffcert`
reports it as a failing, degenerate certificate.

**Scenario B — real mismatch, shrunk:**

```
attempts=5 unique_inputs=5 mismatch_count=4 passed=False
  case="'d'" shrunk=True evals=3  a=('ok', 'D')  b=('ok', 'd')
  case="'c'" shrunk=True evals=1  a=('ok', 'C')  b=('ok', 'c')
  case="'e'" shrunk=True evals=3  a=('ok', 'E')  b=('ok', 'e')
certificate_sha256=4d1b5f68e25d20ed78deaeac9c74df280ff49f64b0ac62d083b845b6830e6d44
```

**Reproducibility and shrinking (verified commands):**

- Running the same certification twice yields the identical
  `certificate_sha256=65d13977…10b8` (see `results/degenerate.certificate.json`).
- `ddmin` on a 20,006-character input reduces it to `'NEEDLE'` in **69**
  evaluations (deterministic, capped at `max_evals`).

## Tests

```bash
python -m unittest discover -s tests -v
```

`24 tests` covering: canonical serialisation determinism, dict/set order
independence, address/UUID/timestamp normalisation (and that it is counted),
unique-vs-attempt de-duplication, degenerate detection, byte-exact value/type and
exception mismatches, ddmin shrinking (str and list) with an eval cap,
certificate determinism, and empty-input handling.

## Quality gates

This is an original library, not an upstream optimisation, so the `-opt-lab`
G1–G5 performance gates do **not** apply (there is no upstream test suite and no
speedup claim). The measurable claims above are covered by:

- **Correctness:** `python -m unittest discover -s tests -v` → `OK (24 tests)`.
- **Determinism:** identical `certificate_sha256` on repeated runs (command in
  the Evidence section).
- **Installability:** `pip install .` succeeds; `import diffcert` and
  `python -m diffcert demo` work from an installed copy.

## Reproduce in three commands

```bash
pip install .
python -m unittest discover -s tests -v
python -m diffcert demo --write results
```

## Environment

- Python 3.12.3 (CPython), Linux x86_64, 4 vCPU.
- No runtime dependencies; standard library only.
- Certificates intentionally contain no timestamps, so digests are reproducible.

## 本轮创新

**B 档.** `diffcert` 把「去重后的独立样本数」做成差分测试的一等公民、可哈希证书：
输入按 canonical 字节 SHA-256 去重后同时报告 `attempts` 与 `unique_inputs`，
重复率超阈值即判 `degenerate` 且永不 pass；并对被掩码的非确定字段计数、对不一致
输入做 ddmin 最小化、证书无时间戳因而 `certificate_sha256` 可跨机复现。
与既有做法不同的是：它不是又一个跑得更快的库，而是把「2000 次循环其实只测了 1 个
输入」这个在创新台账里被反复点名的测量作弊，变成一个当场可证伪的失败证书
（demo 里 2000 attempts → 1 unique，directly reproducible）。
