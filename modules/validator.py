import os

def validate_password(password: str) -> bool:
    """Comprueba que la contraseña tenga al menos 6 caracteres."""
    return len(password) >= 6

def validate_alias(alias: str) -> bool:
    """Comprueba que el alias no esté vacío ni contenga solo espacios."""
    return bool(alias and alias.strip())

def validate_dname(dn_data: dict) -> bool:
    """Comprueba que el CN esté presente y no vacío."""
    return bool(dn_data.get("CN") and str(dn_data["CN"]).strip())

def check_keystore_exists(keystore_path: str) -> bool:
    """Verifica si el almacén existe en el disco."""
    return os.path.exists(keystore_path)