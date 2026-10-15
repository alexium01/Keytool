import argparse
import getpass
import os

from modules.crypto_utils import (
    generate_rsa_keypair,
    build_distinguished_name,
    create_self_signed_certificate,
    generate_csr_pem
)
from modules.keystore_manager import load_keystore, save_keystore
from modules.validator import validate_password, validate_alias, validate_dname

DEFAULT_KEYSTORE = "keystore.p12"

def cmd_genkeypair():
    print("=== Generación de Par de Claves y Almacén (RSA 2048) ===")
    
    password = getpass.getpass("Introduce la contraseña del KeyStore: ")
    if not validate_password(password):
        print("[-] Error: La contraseña debe tener al menos 6 caracteres.")
        return

    alias = input("Introduce el alias para identificar la clave: ").strip()
    if not validate_alias(alias):
        print("[-] Error: El alias no puede estar vacío.")
        return

    # Escenario de error: Alias duplicado / Almacén existente
    if os.path.exists(DEFAULT_KEYSTORE):
        try:
            load_keystore(DEFAULT_KEYSTORE, password)
            print(f"[-] Error: No se ha generado el par de claves, el alias '{alias}' ya existe en el KeyStore.")
            return
        except ValueError:
            print("[-] Error: El almacén ya existe pero la contraseña introducida es incorrecta.")
            return
        except Exception:
            pass

    # Solicitud interactiva del Distinguished Name
    print("\nIntroduce los datos del titular (Distinguished Name):")
    dn_data = {
        "CN": input("Nombre común (CN, ej. Tu Nombre / Dominio): ").strip(),
        "OU": input("Unidad Organizativa (OU, ej. Seguridad): ").strip(),
        "O":  input("Organización (O, ej. MiUniversidad): ").strip(),
        "L":  input("Localidad (L, ej. Malaga): ").strip(),
        "ST": input("Provincia (ST, ej. Malaga): ").strip(),
        "C":  input("Código de País (C, 2 letras ej. ES): ").strip()
    }

    if not validate_dname(dn_data):
        print("[-] Error: El campo CN (Common Name) es obligatorio.")
        return

    print("\n[+] Generando par de claves RSA de 2048 bits...")
    private_key = generate_rsa_keypair(key_size=2048)
    subject = build_distinguished_name(dn_data)
    certificate = create_self_signed_certificate(private_key, subject, days_valid=365)

    save_keystore(DEFAULT_KEYSTORE, alias, private_key, certificate, password)
    print(f"[+] Almacén KeyStore guardado con éxito en '{DEFAULT_KEYSTORE}' con el alias '{alias}'.")

def cmd_certreq():
    print("=== Extracción de Solicitud de Firma de Certificado (CSR) ===")
    
    if not os.path.exists(DEFAULT_KEYSTORE):
        print(f"[-] Error: El almacén '{DEFAULT_KEYSTORE}' no existe. Genere uno primero con --genkeypair.")
        return

    password = getpass.getpass("Introduce la contraseña del KeyStore: ")
    
    try:
        private_key, certificate, _ = load_keystore(DEFAULT_KEYSTORE, password)
    except (FileNotFoundError, ValueError) as err:
        print(f"[-] {err}")
        return

    csr_pem = generate_csr_pem(private_key, certificate.subject)
    salida_csr = "solicitud.csr"
    
    with open(salida_csr, "wb") as f:
        f.write(csr_pem)

    print(f"[+] Solicitud CSR generada con éxito en formato PEM: '{salida_csr}'.")

def cmd_list():
    """Funcionalidad de Ampliación: Inspeccionar el KeyStore."""
    print("=== Inspección del KeyStore ===")
    if not os.path.exists(DEFAULT_KEYSTORE):
        print(f"[-] Error: El almacén '{DEFAULT_KEYSTORE}' no existe.")
        return

    password = getpass.getpass("Introduce la contraseña del KeyStore: ")
    try:
        _, cert, _ = load_keystore(DEFAULT_KEYSTORE, password)
        print("\n[+] Datos del Certificado almacenado:")
        print(f"    Sujeto:           {cert.subject.rfc4514_string()}")
        print(f"    Emisor:           {cert.issuer.rfc4514_string()}")
        print(f"    Número de serie:  {cert.serial_number}")
        print(f"    Válido hasta:     {cert.not_valid_after_utc}")
    except (FileNotFoundError, ValueError) as err:
        print(f"[-] {err}")

def main():
    parser = argparse.ArgumentParser(
        description="Simulador CLI de Java Keytool en Python.",
        epilog="Ejemplo: python Pytool.py --genkeypair"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--genkeypair", action="store_true", help="Generar un par RSA 2048 y guardarlo en el KeyStore")
    group.add_argument("--certreq", action="store_true", help="Extraer una solicitud de firma CSR en formato PEM")
    group.add_argument("--list", action="store_true", help="[Ampliación] Inspeccionar el contenido del KeyStore")

    args = parser.parse_args()

    if args.genkeypair:
        cmd_genkeypair()
    elif args.certreq:
        cmd_certreq()
    elif args.list:
        cmd_list()

if __name__ == "__main__":
    main()