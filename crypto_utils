import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Genera una clave privada RSA de la longitud solicitada (2048 bits)."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

def build_distinguished_name(dn_data: dict) -> x509.Name:
    """Construye la entidad X.509 a partir de los datos ingresados por el usuario."""
    attributes = []
    mapping = [
        ("CN", NameOID.COMMON_NAME),
        ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
        ("O", NameOID.ORGANIZATION_NAME),
        ("L", NameOID.LOCALITY_NAME),
        ("ST", NameOID.STATE_OR_PROVINCE_NAME),
        ("C", NameOID.COUNTRY_NAME)
    ]
    for key, oid in mapping:
        value = dn_data.get(key)
        if value:
            attributes.append(x509.NameAttribute(oid, value))
    return x509.Name(attributes)

def create_self_signed_certificate(private_key: rsa.RSAPrivateKey, subject: x509.Name, days_valid: int = 365) -> x509.Certificate:
    """Crea un certificado X.509 autofirmado necesario para almacenar la clave en PKCS#12."""
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return cert

def generate_csr_pem(private_key: rsa.RSAPrivateKey, subject: x509.Name) -> bytes:
    """Genera la solicitud de firma (CSR) y la devuelve serializada en formato PEM."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)