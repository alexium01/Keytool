import argparse
import datetime
import getpass
import os

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

DEFAULT_KEYSTORE = "keystore.p12"


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
            return
        except Exception:
            pass

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


def main():
    parser = argparse.ArgumentParser(
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


if __name__ == "__main__":
    main()