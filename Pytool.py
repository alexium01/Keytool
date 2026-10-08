import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_keypair(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Genera par de claves asimétricas RSA de 2048 bits con e=65537."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

def build_distinguished_name(dn_data: dict) -> x509.Name:
    """Construye la entidad X.509 a partir de los datos introducidos."""
    mapping = [
        ("CN", NameOID.COMMON_NAME),
        ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
        ("O", NameOID.ORGANIZATION_NAME),
        ("L", NameOID.LOCALITY_NAME),
        ("ST", NameOID.STATE_OR_PROVINCE_NAME),
        ("C", NameOID.COUNTRY_NAME)
    ]
    attributes = []
    for key, oid in mapping:
        val = dn_data.get(key)
        if val:
            attributes.append(x509.NameAttribute(oid, val))
    return x509.Name(attributes)

def create_self_signed_certificate(private_key: rsa.RSAPrivateKey, subject: x509.Name, days_valid: int = 365) -> x509.Certificate:
    """Crea el certificado X.509 autofirmado para guardarlo en el almacén."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
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

def generate_csr(private_key: rsa.RSAPrivateKey, subject: x509.Name) -> bytes:
    """Genera una solicitud de firma (CSR) y devuelve sus bytes en formato PEM."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)