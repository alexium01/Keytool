# Cifrado simulado (genera bytes crudos aleatorios)
import os
raw_ciphertext = os.urandom(32)

# Convertir a texto alfanumérico romano (0-9, a-f)
hex_text = raw_ciphertext.hex()
print("Salida Hexadecimal:", hex_text)

# Para revertir al descifrar:
recovered_bytes = bytes.fromhex(hex_text)
assert recovered_bytes == raw_ciphertext