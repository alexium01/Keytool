import os
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization

def load_keystore(keystore_path: str, password: str):
    """
    Carga el almacén PKCS#12 y valida la contraseña.
    Retorna una tupla: (private_key, certificate, additional_certificates)
    """
    if not os.path.exists(keystore_path):
        raise FileNotFoundError(f"Error: El almacén '{keystore_path}' no existe.")
    
    try:
        with open(keystore_path, "rb") as f:
            data = f.read()
        return pkcs12.load_key_and_certificates(data, password.encode("utf-8"))
    except ValueError:
        raise ValueError("Error: Contraseña del almacén incorrecta o archivo dañado.")

def save_keystore(keystore_path: str, alias: str, private_key, certificate, password: str):
    """Cifra y persiste la clave privada y el certificado en formato PKCS#12."""
    encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=alias.encode("utf-8"),
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=encryption
    )
    
    with open(keystore_path, "wb") as f:
        f.write(p12_bytes)