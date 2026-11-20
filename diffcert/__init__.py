"""diffcert - differential-testing certificates.

Make the number that matters impossible to fudge:

* de-duplicate candidate inputs by SHA-256 of a canonical serialisation and
  report **unique inputs**, not loop attempts;
* compare two implementations **byte for byte** on every unique input;
* report how many non-deterministic values were masked (so a diff cannot be
  silently "passed" by over-normalising);
* shrink every mismatch with delta debugging to a minimal repro;
* emit a deterministic, timestamp-free certificate JSON whose SHA-256 you can
  reproduce on any machine.
"""

from .canonical import canonical_bytes, canonical_text, sha256_hex
from .certify import Certificate, Mismatch, certify
from .ddmin import ddmin
from .sampleset import SampleSet

__all__ = [
    "canonical_bytes",
    "canonical_text",
    "sha256_hex",
    "Certificate",
    "Mismatch",
    "certify",
    "ddmin",
    "SampleSet",
]

__version__ = "0.1.0"
