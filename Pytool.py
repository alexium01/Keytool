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

def parse_dname_string(dname_str: str) -> dict:
    """Parsea una cadena DNAME en formato 'CN=..., OU=..., O=...'."""
    dn_dict = {}
    if not dname_str:
        return dn_dict
    for part in dname_str.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            dn_dict[k.strip().upper()] = v.strip()
    return dn_dict

def get_password(storepass: str | None, prompt: str = "Introduce la contraseña del KeyStore: ") -> str:
    """Usa la contraseña pasada por parámetro o la solicita interactivamente."""
    if storepass:
        return storepass
    return getpass.getpass(prompt)

def cmd_genkeypair(args):
    print(f"{Color.BOLD}=== Generación de Par de Claves y Almacén ==={Color.END}")
    
    target_keystore = args.keystore or "keystore.p12"
    password = get_password(args.storepass)
    if not validate_password(password):
        print(f"{Color.FAIL}[-] Error: La contraseña debe tener al menos 6 caracteres.{Color.END}")
        return

    alias = args.alias or input("Introduce el alias para identificar la clave: ").strip()
    if not validate_alias(alias):
        print(f"{Color.FAIL}[-] Error: El alias no puede estar vacío.{Color.END}")
        return

    # Escenario de error: Almacén existente / Alias ya presente
    if os.path.exists(target_keystore):
        try:
            load_keystore(target_keystore, password)
            print(f"{Color.FAIL}[-] Error: No se ha generado el par de claves, el alias '{alias}' ya existe en el KeyStore '{target_keystore}'.{Color.END}")
            return
        except ValueError:
            print(f"{Color.FAIL}[-] Error: El almacén '{target_keystore}' ya existe pero la contraseña no coincide.{Color.END}")
            return
        except Exception:
            pass

    # Solicitud o parseo del Distinguished Name
    if args.dname:
        dn_data = parse_dname_string(args.dname)
    else:
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

    key_size = args.keysize or 2048
    print(f"\n{Color.WARNING}[+] Generando par de claves RSA de {key_size} bits...{Color.END}")
    private_key = generate_rsa_keypair(key_size=key_size)
    subject = build_distinguished_name(dn_data)
    certificate = create_self_signed_certificate(private_key, subject, days_valid=365)

    save_keystore(target_keystore, alias, private_key, certificate, password)
    print(f"{Color.GREEN}[+] Almacén KeyStore guardado con éxito en '{target_keystore}' con el alias '{alias}'.{Color.END}")

def cmd_certreq(args):
    print(f"{Color.BOLD}=== Extracción de Solicitud de Firma de Certificado (CSR) ==={Color.END}")
    target_keystore = args.keystore or "keystore.p12"
    
    if not os.path.exists(target_keystore):
        print(f"{Color.FAIL}[-] Error: El almacén '{target_keystore}' no existe. Genere uno primero con -genkeypair.{Color.END}")
        return

    alias = args.alias or input("Introduce el alias específico: ").strip()
    password = get_password(args.storepass, prompt="Introduce la contraseña del KeyStore y del alias: ")
    
    try:
        private_key, certificate, _ = load_keystore(target_keystore, password)
    except (FileNotFoundError, ValueError) as err:
        print(f"{Color.FAIL}[-] {err}{Color.END}")
        return

    csr_pem = generate_csr_pem(private_key, certificate.subject)
    salida_csr = args.file or (f"{alias}.csr" if alias else "solicitud.csr")
    
    with open(salida_csr, "wb") as f:
        f.write(csr_pem)

    print(f"{Color.GREEN}[+] Solicitud CSR generada con éxito en formato PEM: '{salida_csr}'.{Color.END}")

def cmd_list(args):
    print(f"{Color.BOLD}=== Inspección del KeyStore ==={Color.END}")
    target_keystore = args.keystore or "keystore.p12"
    if not os.path.exists(target_keystore):
        print(f"{Color.FAIL}[-] Error: El almacén '{target_keystore}' no existe.{Color.END}")
        return

    password = get_password(args.storepass)
    try:
        _, cert, _ = load_keystore(target_keystore, password)
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
        epilog="Ejemplo: python Pytool.py -genkeypair -alias mi_clave -keystore almacen.p12",
        add_help=False
    )

    # Grupo de Ayuda estándar y compatible con Java (-help y --help)
    ayuda = parser.add_argument_group("Ayuda")
    ayuda.add_argument("-h", "--help", "-help", action="help", help="Muestra este mensaje de ayuda y termina")

    # Comandos / Operaciones principales
    acciones = parser.add_argument_group("Comandos principales (acciones)")
    group = acciones.add_mutually_exclusive_group(required=True)
    group.add_argument("-genkeypair", "--genkeypair", action="store_true", help="Generar un par de claves y guardarlo en el KeyStore")
    group.add_argument("-certreq", "--certreq", action="store_true", help="Generar una solicitud de firma CSR en formato PEM")
    group.add_argument("-list", "--list", action="store_true", help="[Ampliación] Inspeccionar el contenido del KeyStore")

    # Modificadores y parámetros
    opciones = parser.add_argument_group("Opciones y parámetros")
    opciones.add_argument("-alias", "--alias", type=str, help="Alias identificador en el KeyStore")
    opciones.add_argument("-keystore", "--keystore", type=str, default="keystore.p12", help="Ruta del archivo KeyStore")
    opciones.add_argument("-keysize", "--keysize", type=int, default=2048, help="Tamaño de clave RSA en bits (por defecto: 2048)")
    opciones.add_argument("-dname", "--dname", type=str, help="Nombre distinguido X.500 (ej: 'CN=Nombre, O=Org, C=ES')")
    opciones.add_argument("-file", "--file", type=str, help="Ruta de salida para el archivo CSR")
    opciones.add_argument("-storepass", "--storepass", type=str, help="Contraseña del KeyStore")

    args = parser.parse_args()

    if args.genkeypair:
        cmd_genkeypair(args)
    elif args.certreq:
        cmd_certreq(args)
    elif args.list:
        cmd_list(args)

if __name__ == "__main__":
    main()