import random
import unittest

from diffcert import SampleSet, canonical_bytes, canonical_text, certify, ddmin
from diffcert.canonical import _default


class TestCanonical(unittest.TestCase):
    def test_dict_order_does_not_matter(self):
        a, _ = canonical_bytes({"b": 1, "a": 2})
        b, _ = canonical_bytes({"a": 2, "b": 1})
        self.assertEqual(a, b)

    def test_deterministic_repeated(self):
        obj = {"x": [1, 2, {"y": "z"}], "s": "héllo"}
        self.assertEqual(canonical_bytes(obj)[0], canonical_bytes(obj)[0])

    def test_set_is_order_independent(self):
        a, _ = canonical_bytes({"s": {3, 1, 2}})
        b, _ = canonical_bytes({"s": {2, 3, 1}})
        self.assertEqual(a, b)

    def test_unknown_object_falls_back_to_repr(self):
        class Thing:
            def __repr__(self):
                return "Thing(42)"

        data, _ = canonical_bytes(Thing())
        self.assertIn(b"Thing(42)", data)
        self.assertIn(b"__repr__", data)

    def test_address_normalization_masks_and_counts(self):
        text, counts = canonical_text("object at 0x7f9b2c1d3e40 here")
        self.assertIn("object at <addr> here", text)
        self.assertEqual(counts.get("addr"), 1)

    def test_two_different_addresses_compare_equal_after_normalization(self):
        a, _ = canonical_bytes("obj 0xAAAA")
        b, _ = canonical_bytes("obj 0xBBBB")
        self.assertEqual(a, b)

    def test_normalization_can_be_disabled(self):
        a, ca = canonical_bytes("obj 0xAAAA", normalize=False)
        b, _ = canonical_bytes("obj 0xBBBB", normalize=False)
        self.assertNotEqual(a, b)
        self.assertEqual(ca, {})


class TestSampleSet(unittest.TestCase):
    def test_unique_vs_attempts(self):
        s = SampleSet()
        for value in [1, 1, 2, 3, 3, 3]:
            s.add(value)
        self.assertEqual(s.attempts, 6)
        self.assertEqual(s.unique, 3)
        self.assertAlmostEqual(s.duplicate_rate, 0.5)

    def test_returns_true_only_for_new(self):
        s = SampleSet()
        self.assertTrue(s.add({"a": 1}))
        self.assertFalse(s.add({"a": 1}))
        self.assertTrue(s.add({"a": 2}))

    def test_degenerate_flag_on_identical_stream(self):
        s = SampleSet()
        for _ in range(2000):
            s.add([1, 2, 3])
        self.assertEqual(s.attempts, 2000)
        self.assertEqual(s.unique, 1)
        self.assertTrue(s.is_degenerate())

    def test_not_degenerate_on_distinct_stream(self):
        s = SampleSet()
        for i in range(50):
            s.add(i)
        self.assertFalse(s.is_degenerate())


class TestDdmin(unittest.TestCase):
    def test_shrinks_to_single_triggering_char(self):
        # Only inputs containing 'Z' disagree with the reference.
        def fails(candidate):
            return isinstance(candidate, str) and "Z" in candidate

        minimal, evals = ddmin("abcdefghijZklmnopqrstuvwxyz", fails)
        self.assertEqual(minimal, "Z")
        self.assertGreater(evals, 0)

    def test_shrinks_list_to_single_element(self):
        def fails(candidate):
            return isinstance(candidate, list) and 7 in candidate

        minimal, _ = ddmin([1, 2, 3, 4, 5, 6, 7, 8, 9], fails)
        self.assertEqual(minimal, [7])

    def test_respects_eval_cap(self):
        def fails(candidate):
            return isinstance(candidate, str) and "x" in candidate

        _, evals = ddmin("x" + "a" * 5000, fails, max_evals=10)
        self.assertLessEqual(evals, 10)


class TestCertify(unittest.TestCase):
    def test_identical_implementations_pass(self):
        cert = certify(lambda x: x * 2, lambda x: x * 2, [1, 2, 3, 4, 5])
        self.assertTrue(cert.passed)
        self.assertEqual(len(cert.mismatches), 0)
        self.assertEqual(cert.unique_inputs, 5)
        self.assertFalse(cert.degenerate)

    def test_real_mismatch_is_detected_and_shrunk(self):
        cert = certify(str.upper, str.lower, ["Hello World", "abc"], name_a="upper", name_b="lower")
        self.assertFalse(cert.passed)
        self.assertGreaterEqual(len(cert.mismatches), 1)
        # every mismatch is shrunk to a single character
        self.assertTrue(all(len(eval(m.case_repr)) == 1 for m in cert.mismatches))

    def test_degenerate_generator_is_flagged(self):
        def gen(n):
            for _ in range(n):
                rng = random.Random(4321)  # reseeded every iteration -> same sample
                yield [rng.randint(0, 99) for _ in range(6)]

        cert = certify(sum, sum, gen(2000))
        self.assertEqual(cert.attempts, 2000)
        self.assertEqual(cert.unique_inputs, 1)
        self.assertTrue(cert.degenerate)
        self.assertFalse(cert.passed)  # degenerate certificates never pass

    def test_tuple_vs_type_mismatch_flagged(self):
        # 1 == True and "1" vs true are different canonical bytes
        cert = certify(lambda x: 1, lambda x: True, [0])
        self.assertFalse(cert.passed)
        self.assertEqual(len(cert.mismatches), 1)

    def test_exception_vs_value_is_mismatch(self):
        def boom(x):
            raise ValueError("nope")

        cert = certify(boom, lambda x: x, [1, 2, 3])
        self.assertFalse(cert.passed)
        self.assertEqual(len(cert.mismatches), 3)
        self.assertEqual(cert.mismatches[0].out_a[0], "exc")
        self.assertEqual(cert.to_dict()["mismatches"][0]["out_a"]["raised"], "ValueError")

    def test_same_exception_is_not_mismatch(self):
        def boom(x):
            raise ValueError("same")

        cert = certify(boom, boom, [1, 2])
        self.assertTrue(cert.passed)
        self.assertEqual(len(cert.mismatches), 0)

    def test_certificate_is_deterministic(self):
        cases = [1, 2, 3, 2, 1]
        c1 = certify(lambda x: x + 1, lambda x: x + 2, cases)
        c2 = certify(lambda x: x + 1, lambda x: x + 2, cases)
        self.assertEqual(c1.to_json(), c2.to_json())
        self.assertEqual(c1.digest(), c2.digest())

    def test_empty_cases_pass_and_not_degenerate(self):
        cert = certify(lambda x: x, lambda x: x, [])
        self.assertEqual(cert.attempts, 0)
        self.assertEqual(cert.unique_inputs, 0)
        self.assertFalse(cert.degenerate)
        self.assertTrue(cert.passed)
        self.assertEqual(cert.duplicate_rate, 0.0)

    def test_normalization_counts_surface_in_certificate(self):
        def a(_x):
            return "token 0xDEADBEEF"

        def b(_x):
            return "token 0x12345678"

        cert = certify(a, b, [1])
        # after masking the addresses the outputs are equal -> no mismatch,
        # but the certificate must still disclose that it masked an address.
        self.assertEqual(len(cert.mismatches), 0)
        self.assertEqual(cert.normalization_counts.get("addr"), 2)

    def test_raw_repr_normalizer_fallback_used(self):
        class Weird:
            def __repr__(self):
                return "Weird()"

        self.assertIsInstance(_default(Weird()), dict)


if __name__ == "__main__":
    unittest.main()
