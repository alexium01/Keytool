import argparse
import datetime
import getpass
import os
import sys

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
from modules.keystore_manager import load_keystore, save_keystore
from modules.validator import validate_alias, validate_dname, validate_password

DEFAULT_KEYSTORE = "keystore.p12"


def get_ks_path(args) -> str:
    return args.keystore if args.keystore else DEFAULT_KEYSTORE


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


def get_password(storepass: str | None, prompt: str = "Introduce la contrasena del KeyStore: ") -> str:
    if storepass:
        return storepass
    return getpass.getpass(prompt)


def cmd_genkeypair(args):
    print_header("Generacion de Par de Claves y Almacen (RSA)")
    ks_path = get_ks_path(args)

    password = get_password(args.storepass, "Introduce la contrasena del KeyStore: ")
    if not validate_password(password):
        print_error("La contrasena debe tener al menos 6 caracteres.")
        return

    alias = args.alias if args.alias else input("Introduce el alias para identificar la clave: ").strip()
    if not validate_alias(alias):
        print_error("El alias no puede estar vacio.")
        return

    # Escenario de error: Almacen existente y Alias Duplicado 
    if os.path.exists(ks_path):
        try:
            load_keystore(ks_path, password)
            print_error(f"No se ha generado el par de claves: el alias '{alias}' ya existe en el KeyStore '{ks_path}'.")
            return
        except ValueError:
            print_error(f"El almacen '{ks_path}' ya existe pero la contrasena introducida es incorrecta.")
            return
        except Exception:
            pass

    if args.dname:
        dn_data = parse_dname_string(args.dname)
    else:
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

    key_size = args.keysize if args.keysize else 2048
    print_info(f"Generando par de claves RSA de {key_size} bits...")
    private_key = generate_rsa_keypair(key_size=key_size)
    subject = build_distinguished_name(dn_data)
    certificate = create_self_signed_certificate(private_key, subject, days_valid=365)

    save_keystore(ks_path, alias, private_key, certificate, password)
    print_success(f"Almacen KeyStore guardado con exito en '{ks_path}' con el alias '{alias}'.")


def cmd_certreq(args):
    print_header("Extraccion de Solicitud de Firma de Certificado (CSR)")
    ks_path = get_ks_path(args)

    if not os.path.exists(ks_path):
        print_error(f"El almacen '{ks_path}' no existe. Genere uno primero con -genkeypair.")
        return

    alias = args.alias if args.alias else input("Introduce el alias especifico: ").strip()
    password = get_password(args.storepass, "Introduce la contrasena del KeyStore y del alias: ")

    try:
        private_key, certificate, _ = load_keystore(ks_path, password)
        csr_pem = generate_csr_pem(private_key, certificate.subject)
        out_file = args.file if args.file else (f"{alias}.csr" if alias else "solicitud.csr")

        with open(out_file, "wb") as f:
            f.write(csr_pem)

        print_success(f"Solicitud CSR generada con exito en formato PEM: '{out_file}'.")
    except (FileNotFoundError, ValueError) as err:
        print_error(f"{err}")
    except Exception as err:
        print_error(f"Error inesperado: {err}")


def cmd_list(args):
    print_header("Inspeccion del KeyStore")
    ks_path = get_ks_path(args)

    if not os.path.exists(ks_path):
        print_error(f"El almacen '{ks_path}' no existe.")
        return

    password = get_password(args.storepass, "Introduce la contrasena del KeyStore: ")
    try:
        _, cert, _ = load_keystore(ks_path, password)
        print_info(f"Archivo KeyStore: {ks_path}")
        print(f"\n   Propietario (Sujeto): {cert.subject.rfc4514_string()}")
        print(f"   Emisor:                {cert.issuer.rfc4514_string()}")
        print(f"   Numero de serie:       {cert.serial_number}")
        print(f"   Valido hasta:          {cert.not_valid_after_utc}")
        if getattr(args, "v", False):
            print(f"   Huella SHA-256:        {get_cert_fingerprint(cert)}")
    except (FileNotFoundError, ValueError) as err:
        print_error(f"{err}")
    except Exception as err:
        print_error(f"Error al leer el almacen: {err}")


def cmd_exportcert(args):
    print_header("Exportar Certificado")
    ks_path = get_ks_path(args)
    if not os.path.exists(ks_path):
        print_error(f"El almacen '{ks_path}' no existe.")
        return
    password = get_password(args.storepass, "Introduce la contrasena del KeyStore: ")
    try:
        _, cert, _ = load_keystore(ks_path, password)
        out_file = args.file if args.file else "certificado.crt"
        with open(out_file, "wb") as f:
            f.write(export_cert_pem(cert))
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
    print("  -genkeypair / --genkeypair     Genera un par de claves y un certificado autofirmado.")
    print("  -certreq / --certreq           Genera una solicitud CSR en formato PEM.")
    print("  -list / --list                 Muestra las entradas guardadas en el KeyStore.")
    print("  --exportcert                   Exporta el certificado del almacen a un archivo .crt.")
    print("  --printcert                    Visualiza la informacion de un archivo de certificado PEM.")
    print("  --showdate                     Muestra la fecha del sistema para validacion.")
    print("  --help-ext                     Muestra esta lista extendida de ayuda.")


def main():
    parser = argparse.ArgumentParser(
        description="Simulador CLI de Java Keytool en Python.",
        prog="keytool",
        epilog="Ejemplo: python Pytool.py -genkeypair -alias mi_clave -keystore almacen.p12",
        add_help=False,
    )

    ayuda = parser.add_argument_group("Ayuda")
    ayuda.add_argument("-h", "--help", "-help", action="help", help="Muestra este mensaje de ayuda y termina")

    acciones = parser.add_argument_group("Comandos principales (acciones)")
    group = acciones.add_mutually_exclusive_group(required=True)
    group.add_argument("-genkeypair", "--genkeypair", action="store_true", help="1. Generar par de claves RSA y guardar en KeyStore")
    group.add_argument("-certreq", "--certreq", action="store_true", help="2. Generar solicitud CSR en formato PEM")
    group.add_argument("-list", "--list", action="store_true", help="3. Inspeccionar el contenido del KeyStore")
    group.add_argument("--exportcert", action="store_true", help="4. [Ampliacion] Exportar el certificado a un archivo PEM")
    group.add_argument("--printcert", action="store_true", help="5. [Ampliacion] Imprimir detalles de un certificado externo")
    group.add_argument("--showdate", action="store_true", help="6. [Ampliacion] Mostrar fecha/hora actual del sistema")
    group.add_argument("--help-ext", action="store_true", help="7. [Ampliacion] Mostrar ayuda extendida con descripcion detallada")

    opciones = parser.add_argument_group("Opciones y parametros")
    opciones.add_argument("-alias", "--alias", dest="alias", type=str, help="Alias identificador en el KeyStore")
    opciones.add_argument("-keystore", "--keystore", dest="keystore", type=str, default="keystore.p12", help="Ruta del archivo KeyStore")
    opciones.add_argument("-keysize", "--keysize", dest="keysize", type=int, default=2048, help="Tamano de clave RSA en bits (defecto: 2048)")
    opciones.add_argument("-dname", "--dname", dest="dname", type=str, help="Nombre distinguido X.500 (ej: 'CN=Nombre, O=Org, C=ES')")
    opciones.add_argument("-file", "--file", dest="file", type=str, help="Ruta de archivo de entrada/salida")
    opciones.add_argument("-storepass", "--storepass", dest="storepass", type=str, help="Contrasena del KeyStore")
    opciones.add_argument("-v", action="store_true", help="Modo detallado (Verbose)")

    args = parser.parse_args()

    if args.genkeypair:
        cmd_genkeypair(args)
    elif args.certreq:
        cmd_certreq(args)
    elif args.list:
        cmd_list(args)
    elif args.exportcert:
        cmd_exportcert(args)
    elif args.printcert:
        cmd_printcert(args)
    elif args.showdate:
        print_info(f"Fecha actual del sistema: {datetime.datetime.now()}")
    elif args.help_ext:
        cmd_help_ext()


if __name__ == "__main__":
    main()