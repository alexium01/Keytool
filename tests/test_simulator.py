import unittest
from modules.validator import validate_password, validate_dname, validate_alias
from modules.crypto_utils import generate_rsa_keypair, build_distinguished_name

class TestKeytoolSimulator(unittest.TestCase):

    def test_validador_password(self):
        self.assertFalse(validate_password("12345"))
        self.assertTrue(validate_password("123456"))

    def test_validador_alias(self):
        self.assertFalse(validate_alias(""))
        self.assertFalse(validate_alias("   "))
        self.assertTrue(validate_alias("miClave"))

    def test_validador_dname(self):
        self.assertFalse(validate_dname({"CN": ""}))
        self.assertTrue(validate_dname({"CN": "Adrian", "C": "ES"}))

    def test_generacion_rsa_2048(self):
        key = generate_rsa_keypair(key_size=2048)
        self.assertEqual(key.key_size, 2048)

if __name__ == "__main__":
    unittest.main()