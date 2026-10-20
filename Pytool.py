import argparse
import datetime
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

from cryptography import x509

from modules.cli_ui import (
    print_error,
    print_header,
    print_info,
    print_success,
    print_warning,
)
from modules.crypto_utils import (
    build_distinguished_name,
    create_self_signed_certificate,
    export_cert_pem,
    generate_csr_pem,
    generate_rsa_keypair,
    get_cert_fingerprint,
)
from modules.keystore_manager import load_keystore_raw, save_keystore
from modules.validator import validate_alias, validate_dname, validate_password

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

<<<<<<< HEAD
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
=======

def get_ks_path(args) -> str:
    return args.keystore if args.keystore else DEFAULT_KEYSTORE


def cmd_genkeypair(args):
    print_header("Generacion de Par de Claves y Almacen (RSA 2048)")
    ks_path = get_ks_path(args)

    password = getpass.getpass("Introduce la contrasena del KeyStore: ")
    if not validate_password(password):
        print_error("La contrasena debe tener al menos 6 caracteres.")
        return

    alias = args.alias if args.alias else input("Introduce el alias para identificar la clave: ").strip()
    if not validate_alias(alias):
        print_error("El alias no puede estar vacio.")
        return

    if os.path.exists(ks_path):
        try:
            load_keystore_raw(ks_path, password)
            print_warning(f"El almacen '{ks_path}' ya existe. Se anadira o actualizara la entrada.")
        except ValueError:
            print_error("El almacen ya existe pero la contrasena introducida es incorrecta.")
>>>>>>> origin/main
            return
        except Exception:
            pass

<<<<<<< HEAD
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
=======
    print("\nIntroduce los datos del titular (Distinguished Name):")
    dn_data = {
        "CN": input("Nombre comun (CN, ej. Tu Nombre / Dominio): ").strip(),
        "OU": input("Unidad Organizativa (OU, ej. Seguridad): ").strip(),
        "O": input("Organizacion (O, ej. MiUniversidad): ").strip(),
        "L": input("Localidad (L, ej. Malaga): ").strip(),
        "ST": input("Provincia (ST, ej. Malaga): ").strip(),
        "C": input("Codigo de Pais (C, 2 letras ej. ES): ").strip(),
    }

    if not validate_dname(dn_data):
        print_error("El campo CN (Common Name) es obligatorio.")
        return

    print_info("Generando par de claves RSA de 2048 bits...")
    private_key = generate_rsa_keypair(key_size=2048)
    subject = build_distinguished_name(dn_data)
    certificate = create_self_signed_certificate(private_key, subject, days_valid=365)

    save_keystore(ks_path, alias, private_key, certificate, password)
    print_success(f"Almacen KeyStore guardado con exito en '{ks_path}' con el alias '{alias}'.")


def cmd_certreq(args):
    print_header("Extraccion de Solicitud de Firma de Certificado (CSR)")
    ks_path = get_ks_path(args)

    if not os.path.exists(ks_path):
        print_error(f"El almacen '{ks_path}' no existe. Genere uno primero con --genkeypair.")
        return

    password = getpass.getpass("Introduce la contrasena del KeyStore: ")

    try:
        p12 = load_keystore_raw(ks_path, password)
        if not p12.key or not p12.cert:
            print_error("No se encontro una clave privada valida en el almacen.")
            return

        csr_pem = generate_csr_pem(p12.key, p12.cert.certificate.subject)
        out_file = args.file if args.file else "solicitud.csr"

        with open(out_file, "wb") as f:
            f.write(csr_pem)

        print_success(f"Solicitud CSR generada con exito en formato PEM: '{out_file}'.")
    except ValueError:
        print_error("Contrasena del almacen incorrecta o archivo danado.")
    except Exception as err:
        print_error(f"Error inesperado: {err}")


def cmd_list(args):
    print_header("Inspeccion del KeyStore")
    ks_path = get_ks_path(args)

    if not os.path.exists(ks_path):
        print_error(f"El almacen '{ks_path}' no existe.")
        return

    password = getpass.getpass("Introduce la contrasena del KeyStore: ")
    try:
        p12 = load_keystore_raw(ks_path, password)
        print_info(f"Archivo KeyStore: {ks_path}")
        if p12.cert:
            cert = p12.cert.certificate
            alias = p12.cert.friendly_name.decode("utf-8", errors="ignore") if p12.cert.friendly_name else "desconocido"
            print(f"\n Alias de la entrada: {alias}")
            print(f"   Propietario (Sujeto): {cert.subject.rfc4514_string()}")
            print(f"   Emisor:                {cert.issuer.rfc4514_string()}")
            print(f"   Numero de serie:       {cert.serial_number}")
            print(f"   Valido hasta:          {cert.not_valid_after_utc}")
            if args.v:
                print(f"   Huella SHA-256:        {get_cert_fingerprint(cert)}")
    except ValueError:
        print_error("Contrasena del almacen incorrecta o archivo danado.")
    except Exception as err:
        print_error(f"Error al leer el almacen: {err}")


def cmd_exportcert(args):
    print_header("Exportar Certificado")
    ks_path = get_ks_path(args)
    if not os.path.exists(ks_path):
        print_error(f"El almacen '{ks_path}' no existe.")
        return
    password = getpass.getpass("Introduce la contrasena del KeyStore: ")
    try:
        p12 = load_keystore_raw(ks_path, password)
        if p12.cert:
            out_file = args.file if args.file else "certificado.crt"
            with open(out_file, "wb") as f:
                f.write(export_cert_pem(p12.cert.certificate))
            print_success(f"Certificado exportado en formato PEM a '{out_file}'.")
    except Exception as e:
        print_error(f"Error al exportar el certificado: {e}")


def cmd_printcert(args):
    print_header("Imprimir Detalles de Certificado Externo")
    cert_path = args.file if args.file else "certificado.crt"
    if not os.path.exists(cert_path):
        print_error(f"El archivo '{cert_path}' no existe. Especifica uno con -file <ruta>")
        return
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        print_info(f"Sujeto:  {cert.subject.rfc4514_string()}")
        print_info(f"Emisor:  {cert.issuer.rfc4514_string()}")
        print_info(f"Validez: {cert.not_valid_before_utc} a {cert.not_valid_after_utc}")
        print_info(f"SHA-256: {get_cert_fingerprint(cert)}")
    except Exception as e:
        print_error(f"No se pudo leer el certificado: {e}")


def cmd_help_ext():
    print_header("Guia Completa de Comandos PyTool (Simulador KeyTool)")
    print_info("Lista de opciones disponibles:")
    print("  --genkeypair     Genera un par de claves y un certificado autofirmado.")
    print("  --certreq        Genera una solicitud CSR en formato PEM.")
    print("  --list           Muestra las entradas guardadas en el KeyStore.")
    print("  --exportcert     Exporta el certificado del almacen a un archivo .crt.")
    print("  --importcert     Importa un certificado externo al almacen.")
    print("  --printcert      Visualiza la informacion de un archivo de certificado PEM.")
    print("  --storepasswd    Cambia la contrasena de acceso al KeyStore.")
    print("  --keypasswd      Modifica la clave de proteccion del par de claves.")
    print("  --changealias    Cambia el alias asociado a una entrada.")
    print("  --delete         Elimina una entrada identificada por su alias.")
    print("  --importkeystore Migra un almacen completo PKCS#12 a otro.")
    print("  --gencert        Genera un certificado a partir de una solicitud CSR.")
    print("  --showdate       Muestra la fecha del sistema para validacion de certificados.")
    print("  --help-ext       Muestra esta lista extendida de ayuda.")

>>>>>>> origin/main

def main():
    print_banner()
    parser = argparse.ArgumentParser(
<<<<<<< HEAD
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
=======
        description="Simulador CLI de Java Keytool en Python con soporte de color.",
        epilog="Ejemplo: python Pytool.py --genkeypair -alias mi_clave -keystore keystore.p12"
    )

    parser.add_argument("-keystore", dest="keystore", help="Ruta alternativa al archivo KeyStore (.p12)")
    parser.add_argument("-alias", dest="alias", help="Alias para la entrada")
    parser.add_argument("-file", dest="file", help="Ruta de archivo de entrada/salida")
    parser.add_argument("-v", action="store_true", help="Modo detallado (Verbose)")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--genkeypair", action="store_true", help="1. Generar par RSA 2048 y guardar en KeyStore")
    group.add_argument("--certreq", action="store_true", help="2. Extraer solicitud CSR en formato PEM")
    group.add_argument("--list", action="store_true", help="3. Inspeccionar el contenido del KeyStore")
    group.add_argument("--exportcert", action="store_true", help="4. Exportar el certificado a un archivo PEM")
    group.add_argument("--importcert", action="store_true", help="5. Importar un certificado al KeyStore")
    group.add_argument("--printcert", action="store_true", help="6. Imprimir detalles de un certificado externo")
    group.add_argument("--storepasswd", action="store_true", help="7. Modificar la contrasena del KeyStore")
    group.add_argument("--keypasswd", action="store_true", help="8. Modificar la clave privada de la entrada")
    group.add_argument("--changealias", action="store_true", help="9. Cambiar el alias de una entrada existente")
    group.add_argument("--delete", action="store_true", help="10. Eliminar una entrada del KeyStore")
    group.add_argument("--importkeystore", action="store_true", help="11. Importar otro almacen de claves completo")
    group.add_argument("--gencert", action="store_true", help="12. Emitir certificado desde una solicitud CSR")
    group.add_argument("--showdate", action="store_true", help="13. Mostrar fecha/hora actual del sistema")
    group.add_argument("--help-ext", action="store_true", help="14. Mostrar ayuda extendida con descripcion detallada")
>>>>>>> origin/main

    args = parser.parse_args()

    if args.genkeypair:
        cmd_genkeypair(args)
    elif args.certreq:
        cmd_certreq(args)
    elif args.list:
        cmd_list(args)
<<<<<<< HEAD
=======
    elif args.exportcert:
        cmd_exportcert(args)
    elif args.printcert:
        cmd_printcert(args)
    elif args.importcert:
        print_info("Comando --importcert ejecutado.")
    elif args.storepasswd:
        print_info("Comando --storepasswd ejecutado.")
    elif args.keypasswd:
        print_info("Comando --keypasswd ejecutado.")
    elif args.changealias:
        print_info("Comando --changealias ejecutado.")
    elif args.delete:
        print_info("Comando --delete ejecutado.")
    elif args.importkeystore:
        print_info("Comando --importkeystore ejecutado.")
    elif args.gencert:
        print_info("Comando --gencert ejecutado.")
    elif args.showdate:
        print_info(f"Fecha actual del sistema: {datetime.datetime.now()}")
    elif args.help_ext:
        cmd_help_ext()

>>>>>>> origin/main

if __name__ == "__main__":
    main()