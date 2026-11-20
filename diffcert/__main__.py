"""Command line entry point: ``python -m diffcert demo``.

The demo ships two hand-checked scenarios so the tool's claims are auditable:

A. a *degenerate* generator that reseeds its RNG inside the loop, producing
   2,000 attempts that are all the same input -> the certificate reports
   ``unique_inputs = 1`` and ``degenerate = true``;
B. two implementations that really disagree, where the mismatch is shrunk to a
   one-element repro.

Run with ``--json`` for the raw certificate, or ``--write DIR`` to also save
the certificate files.
"""

from __future__ import annotations

import argparse
import os
import random
import sys

from .certify import certify


def _degenerate_cases(n: int):
    """The classic bug: a fresh RNG is seeded inside the loop."""
    for _ in range(n):
        rng = random.Random(4321)
        yield [rng.randint(0, 99) for _ in range(6)]


def _upper(s: str) -> str:
    return s.upper()


def _lower(s: str) -> str:
    return s.lower()


def run_demo(write_dir: str | None = None) -> int:
    a = certify(
        lambda xs: sum(xs),
        lambda xs: sum(xs),
        _degenerate_cases(2000),
        name_a="sum",
        name_b="sum",
    )
    b = certify(
        _upper,
        _lower,
        ["Hello World", "", "abc", "MixedCase", "ZZZ and more text"],
        name_a="upper",
        name_b="lower",
    )

    print("== Scenario A: degenerate random generator ==")
    print(
        "attempts=%d unique_inputs=%d duplicate_rate=%.4f degenerate=%s passed=%s"
        % (a.attempts, a.unique_inputs, a.duplicate_rate, a.degenerate, a.passed)
    )
    print("certificate_sha256=%s" % a.digest())

    print("\n== Scenario B: real mismatch, shrunk ==")
    print(
        "attempts=%d unique_inputs=%d mismatch_count=%d passed=%s"
        % (b.attempts, b.unique_inputs, len(b.mismatches), b.passed)
    )
    for m in b.mismatches[:3]:
        print(
            "  case=%r shrunk=%s evals=%d  a=%s  b=%s"
            % (m.case_repr, m.shrunk, m.shrink_evals, m.out_a, m.out_b)
        )
    print("certificate_sha256=%s" % b.digest())

    if write_dir:
        os.makedirs(write_dir, exist_ok=True)
        for label, cert in (("degenerate", a), ("mismatch", b)):
            path = os.path.join(write_dir, "%s.certificate.json" % label)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(cert.to_json())
            print("wrote %s" % path)

    if write_dir and "--json" in sys.argv:
        print("\n" + a.to_json())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="diffcert", description=__doc__)
    sub = parser.add_subparsers(dest="command")
    demo = sub.add_parser("demo", help="run the built-in auditable demo")
    demo.add_argument("--json", action="store_true", help="also print raw JSON")
    demo.add_argument("--write", metavar="DIR", default=None, help="write certificates to DIR")
    args = parser.parse_args(argv)

    if args.command == "demo":
        return run_demo(write_dir=args.write)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
