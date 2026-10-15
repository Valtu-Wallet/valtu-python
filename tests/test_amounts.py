import unittest
from decimal import Decimal

from valtu import from_base_units, to_base_units


class AmountsTest(unittest.TestCase):
    def test_to_base_units(self):
        self.assertEqual(to_base_units("25.5", 6), "25500000")
        self.assertEqual(to_base_units("0.000001", 6), "1")
        self.assertEqual(to_base_units(".5", 2), "50")
        self.assertEqual(to_base_units(3, 18), "3000000000000000000")
        self.assertEqual(to_base_units(Decimal("1.10"), 2), "110")
        self.assertEqual(to_base_units("1.2300", 2), "123")

    def test_refuses_bad_input(self):
        for bad in ["", ".", "-1", "1e5", "abc", "1.2.3"]:
            with self.assertRaises(ValueError, msg=bad):
                to_base_units(bad, 6)
        with self.assertRaises(ValueError):
            to_base_units("0.0000001", 6)
        with self.assertRaises(TypeError):
            to_base_units(0.1, 6)  # type: ignore[arg-type]

    def test_from_base_units(self):
        self.assertEqual(from_base_units("25500000", 6), "25.5")
        self.assertEqual(from_base_units(1, 6), "0.000001")
        self.assertEqual(from_base_units("100", 0), "100")
        self.assertEqual(from_base_units("-150", 2), "-1.5")
        self.assertEqual(from_base_units(to_base_units("123.456789", 18), 18), "123.456789")


if __name__ == "__main__":
    unittest.main()
