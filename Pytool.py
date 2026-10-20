import argparse
import getpass
import os
import sys

# Colores ANSI para la terminal
class Color:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""{Color.CYAN}{Color.BOLD}
    ╔════════════════════════════════════════════════╗
    ║                KEYTOOL SIMULATOR               ║
    ║        Módulo de Criptografía Autónoma         ║
    ╚════════════════════════════════════════════════╝
    {Color.END}"""
    print(banner)

from modules.crypto_utils import (
    generate_rsa_keypair,
    build_distinguished_name,
    create_self_signed_certificate,
    generate_csr_pem
)
from modules.keystore_manager import load_keystore, save_keystore
from modules.validator import validate_password, validate_alias, validate_dname

DEFAULT_KEYSTORE = "keystore.p12"

def cmd_genkeypair(args):
    print(f"{Color.BOLD}=== Generación de Par de Claves y Almacén (RSA 2048) ==={Color.END}")
    
    password = getpass.getpass("Introduce la contraseña del KeyStore: ")
    if not validate_password(password):
        print(f"{Color.FAIL}[-] Error: La contraseña debe tener al menos 6 caracteres.{Color.END}")
        return

    alias = args.alias or input("Introduce el alias para identificar la clave: ").strip()
    if not validate_alias(alias):
        print(f"{Color.FAIL}[-] Error: El alias no puede estar vacío.{Color.END}")
        return

    # Escenario de error: Comprobar si el archivo existe y validar alias duplicado dentro del PKCS#12
    if os.path.exists(DEFAULT_KEYSTORE):
        try:
            # En PKCS#12 simple, si cargamos bien pero el alias coincide o ya hay una entrada principal
            _, _, aliases = load_keystore_with_aliases(DEFAULT_KEYSTORE, password) # O control de alias
            # Nota: Si tu keystore_manager soporta multiples alias, se valida aquí.
        except ValueError:
            print(f"{Color.FAIL}[-] Error: Contraseña incorrecta para el almacén existente.{Color.END}")
            return
        except Exception:
            pass

    # Solicitud interactiva del Distinguished Name
    print(f"\n{Color.CYAN}Introduce los datos del titular (Distinguished Name):{Color.END}")
    dn_data = {
        "CN": input("Nombre común (CN, ej. Tu Nombre / Dominio): ").strip(),
        "OU": input("Unidad Organizativa (OU, ej. Seguridad): ").strip(),
        "O":  input("Organización (O, ej. MiUniversidad): ").strip(),
        "L":  input("Localidad (L, ej. Malaga): ").strip(),
        "ST": input("Provincia (ST, ej. Malaga): ").strip(),
        "C":  input("Código de País (C, 2 letras ej. ES): ").strip()
    }

    if not validate_dname(dn_data):
        print(f"{Color.FAIL}[-] Error: El campo CN (Common Name) es obligatorio.{Color.END}")
        return

    print(f"\n{Color.WARNING}[+] Generando par de claves RSA de 2048 bits...{Color.END}")
    private_key = generate_rsa_keypair(key_size=2048)
    subject = build_distinguished_name(dn_data)
    certificate = create_self_signed_certificate(private_key, subject, days_valid=365)

    save_keystore(DEFAULT_KEYSTORE, alias, private_key, certificate, password)
    print(f"{Color.GREEN}[+] Almacén KeyStore guardado con éxito en '{DEFAULT_KEYSTORE}' con el alias '{alias}'.{Color.END}")

def cmd_certreq(args):
    print(f"{Color.BOLD}=== Extracción de Solicitud de Firma de Certificado (CSR) ==={Color.END}")
    
    if not os.path.exists(DEFAULT_KEYSTORE):
        print(f"{Color.FAIL}[-] Error: El almacén '{DEFAULT_KEYSTORE}' no existe. Genere uno primero con --genkeypair.{Color.END}")
        return

    alias = args.alias or input("Introduce el alias del certificado: ").strip()
    password = getpass.getpass("Introduce la contraseña del KeyStore: ")
    
    try:
        private_key, certificate, _ = load_keystore(DEFAULT_KEYSTORE, password)
    except (FileNotFoundError, ValueError) as err:
        print(f"{Color.FAIL}[-] {err}{Color.END}")
        return

    csr_pem = generate_csr_pem(private_key, certificate.subject)
    salida_csr = args.file or f"{alias}.csr"
    
    with open(salida_csr, "wb") as f:
        f.write(csr_pem)

    print(f"{Color.GREEN}[+] Solicitud CSR generada con éxito en formato PEM: '{salida_csr}'.{Color.END}")

def cmd_list():
    print(f"{Color.BOLD}=== Inspección del KeyStore ==={Color.END}")
    if not os.path.exists(DEFAULT_KEYSTORE):
        print(f"{Color.FAIL}[-] Error: El almacén '{DEFAULT_KEYSTORE}' no existe.{Color.END}")
        return

    password = getpass.getpass("Introduce la contraseña del KeyStore: ")
    try:
        _, cert, _ = load_keystore(DEFAULT_KEYSTORE, password)
        print(f"\n{Color.GREEN}[+] Datos del Certificado almacenado:{Color.END}")
        print(f"    Sujeto:           {cert.subject.rfc4514_string()}")
        print(f"    Emisor:           {cert.issuer.rfc4514_string()}")
        print(f"    Número de serie:  {cert.serial_number}")
        print(f"    Válido hasta:     {cert.not_valid_after_utc}")
    except (FileNotFoundError, ValueError) as err:
        print(f"{Color.FAIL}[-] {err}{Color.END}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Simulador CLI de Java Keytool en Python.",
        prog="keytool",
        epilog="Ejemplo: python Pytool.py --genkeypair -alias mi_clave"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--genkeypair", action="store_true", help="Generar un par RSA 2048 y guardarlo en el KeyStore")
    group.add_argument("--certreq", action="store_true", help="Extraer una solicitud de firma CSR en formato PEM")
    group.add_argument("--list", action="store_true", help="[Ampliación] Inspeccionar el contenido del KeyStore")

    parser.add_argument("-alias", "--alias", type=str, help="Alias para identificar la entrada en el KeyStore")
    parser.add_argument("-keystore", "--keystore", type=str, help="Ruta del archivo KeyStore")
    parser.add_argument("-file", "--file", type=str, help="Ruta del archivo de salida (CSR)")

    args = parser.parse_args()

    if args.genkeypair:
        cmd_genkeypair(args)
    elif args.certreq:
        cmd_certreq(args)
    elif args.list:
        cmd_list()

if __name__ == "__main__":
    main()