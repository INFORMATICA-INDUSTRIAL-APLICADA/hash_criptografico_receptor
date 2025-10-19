# import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timedelta, timezone

ALGORITMO_FIRMA_PSS = "RSASSA-PSS-SHA256"
ALGORITMO_FIRMA_PKCS1V15 = "RSASSA-PKCS1v15-SHA256"


def generar_clave_privada(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Generates a new RSA private key.

    Args:
        key_size (int, optional): The length of the modulus in bits. Defaults to 2048.

    Returns:
        rsa.RSAPrivateKey: The generated RSA private key object.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def bytes_a_clave_privada(private_key_bytes: bytes) -> rsa.RSAPrivateKey:
    """
    Deserializa una clave privada RSA desde bytes en formato PEM.

    Args:
        private_key_bytes (bytes): Bytes de la clave privada en formato PEM.

    Returns:
        rsa.RSAPrivateKey: Objeto que representa la clave privada RSA cargada.
    """
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None)

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Los bytes proporcionados no contienen una clave RSA válida.")

    return private_key


def clave_privada_a_bytes(private_key: rsa.RSAPrivateKey, password: bytes | None = None) -> bytes:
    """
    Serializes an RSA private key to PEM-encoded bytes, optionally encrypting it with a password.
    Args:
        private_key (rsa.RSAPrivateKey): The RSA private key to serialize.
        password (bytes | None, optional): The password to encrypt the private key with. If None, the key is not encrypted.
    Returns:
        bytes: The PEM-encoded private key, encrypted if a password is provided, otherwise unencrypted.
    """
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def certificado_a_bytes(cert: x509.Certificate) -> bytes:
    """
    Converts an x509.Certificate object to its PEM-encoded byte representation.

    Args:
        cert (x509.Certificate): The certificate to be converted.

    Returns:
        bytes: The PEM-encoded bytes of the certificate.
    """
    return cert.public_bytes(serialization.Encoding.PEM)


def crear_certificado(
    nombre_comun_sujeto: str,
    clave_publica_sujeto: rsa.RSAPublicKey,
    clave_privada_emisor: rsa.RSAPrivateKey,
    nombre_comun_emisor: str,
    es_ca: bool,
    dias_validez: int,
    emisor_country: str = "ES",
    emisor_organization: str = "Informática Industrial Aplicada"
) -> x509.Certificate:
    """
    Crea y firma un certificado X.509 usando las claves y datos proporcionados.
    Args:
        nombre_comun_sujeto (str): Nombre común (CN) del sujeto al que se emite el certificado.
        clave_publica_sujeto (rsa.RSAPublicKey): Clave pública del sujeto.
        clave_privada_emisor (rsa.RSAPrivateKey): Clave privada del emisor (usada para firmar el certificado).
        nombre_comun_emisor (str): Nombre común (CN) del emisor del certificado.
        es_ca (bool): Indica si el certificado es para una Autoridad Certificadora (CA).
        dias_validez (int): Número de días de validez del certificado.
        emisor_country (str, optional): País del emisor. Por defecto "ES".
        emisor_organization (str, optional): Organización del emisor. Por defecto "Informática Industrial Aplicada".
    Returns:
        x509.Certificate: Certificado X.509 firmado.
    Notas:
        - Si el nombre común del emisor y del sujeto son iguales, el certificado será autofirmado (típico de una CA raíz).
        - La extensión BasicConstraints se añade como crítica para indicar si el certificado es de CA.
    """
    # 1. Definir el Sujeto (a quién se le emite el certificado)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, emisor_country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, emisor_organization),
        x509.NameAttribute(NameOID.COMMON_NAME, nombre_comun_sujeto),
    ])

    # 2. Definir el Emisor (quién firma el certificado)
    # Si el nombre del emisor y del sujeto son el mismo, es autofirmado (típico de una CA raíz)
    if nombre_comun_emisor == nombre_comun_sujeto:
        issuer = subject
    else:
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, emisor_country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, emisor_organization),
            x509.NameAttribute(NameOID.COMMON_NAME, nombre_comun_emisor),
        ])

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(clave_publica_sujeto)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=dias_validez))
    )

    # Extensiones básicas
    builder = builder.add_extension(x509.BasicConstraints(ca=es_ca, path_length=None), critical=True)

    # Key Usage según tipo de certificado
    if es_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    # Identificadores de clave
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(clave_publica_sujeto),
        critical=False,
    )

    try:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(clave_privada_emisor.public_key())
        builder = builder.add_extension(aki, critical=False)
    except Exception:
        pass

    # Extended Key Usage para certificados de entidad final
    if not es_ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )

    certificate = builder.sign(private_key=clave_privada_emisor, algorithm=hashes.SHA256())
    return certificate


def cargar_clave_privada(ruta_fichero: str) -> rsa.RSAPrivateKey:
    """
    Carga una clave privada RSA desde un archivo en formato PEM.
    Args:
        ruta_fichero (str): Ruta al archivo que contiene la clave privada en formato PEM.
    Returns:
        rsa.RSAPrivateKey: Objeto que representa la clave privada RSA cargada.
    Raises:
        TypeError: Si el archivo no contiene una clave privada RSA válida.
        FileNotFoundError: Si el archivo especificado no existe.
        ValueError: Si el archivo no contiene una clave privada válida o está corrupto.
    """
    with open(ruta_fichero, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Comprobamos que la clave cargada es del tipo que esperamos
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError(f"El fichero {ruta_fichero} no contiene una clave RSA válida.")

    # Después de la comprobación, Pylance ya sabe que el tipo es RSAPrivateKey
    return private_key


def cargar_certificado(ruta_fichero: str) -> x509.Certificate:
    """
    Carga un certificado X.509 desde un archivo en formato PEM.
    Args:
        ruta_fichero (str): Ruta al archivo que contiene el certificado en formato PEM.
    Returns:
        x509.Certificate: Objeto que representa el certificado X.509 cargado.
    Raises:
        FileNotFoundError: Si el archivo especificado no existe.
        ValueError: Si el archivo no contiene un certificado válido o está corrupto.
    """
    with open(ruta_fichero, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return cert


def bytes_a_certificado(cert_bytes: bytes) -> x509.Certificate:
    """
    Convierte bytes PEM a un objeto de certificado X.509.

    Args:
        cert_bytes (bytes): Bytes del certificado en formato PEM.

    Returns:
        x509.Certificate: Objeto que representa el certificado X.509.
    """
    return x509.load_pem_x509_certificate(cert_bytes)

# def _calcula_hash(datos: bytes) -> bytes:
#     """
#     Calculates the SHA-256 cryptographic hash of the given data.

#     Args:
#         datos (bytes): The input data to hash.

#     Returns:
#         bytes: The SHA-256 hash digest of the input data.
#     """
#     objeto_hash = hashlib.sha256(datos)
#     return objeto_hash.digest()


def firmar_datos(private_key: rsa.RSAPrivateKey, datos: bytes, algoritmo: str = "RSASSA-PSS-SHA256") -> bytes:
    """
    Firma los datos proporcionados utilizando una clave privada RSA y el algoritmo especificado.
    Args:
        private_key (rsa.RSAPrivateKey): Clave privada RSA utilizada para firmar los datos.
        datos (bytes): Datos a firmar.
        algoritmo (str, opcional): Algoritmo de firma a utilizar. Puede ser "RSASSA-PSS-SHA256" (por defecto) o "RSASSA-PKCS1v15-SHA256".
    Returns:
        bytes: Firma digital generada.
    Raises:
        ValueError: Si se especifica un algoritmo no soportado.
    """
    if algoritmo == ALGORITMO_FIRMA_PSS:
        pad_scheme = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )
        hash_alg = hashes.SHA256()
    elif algoritmo == ALGORITMO_FIRMA_PKCS1V15:
        pad_scheme = padding.PKCS1v15()
        hash_alg = hashes.SHA256()
    else:
        raise ValueError(f"Algoritmo no soportado: {algoritmo}")

    signature = private_key.sign(datos, pad_scheme, hash_alg)
    return signature


def verificar_emisor(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Verifica si el certificado del emisor fue firmado por la Autoridad Certificadora (CA) de confianza.

    Args:
        cert (x509.Certificate): Certificado del emisor a verificar.
        ca_cert (x509.Certificate): Certificado de la CA de confianza.

    Returns:
        bool: True si la firma es válida y el certificado fue emitido por la CA, False en caso contrario.
    """
    try:
        # 1. Extraemos la clave pública de la CA. Su tipo es genérico.
        ca_public_key = ca_cert.public_key()

        # 2. COMPROBACIÓN DE TIPO (LA SOLUCIÓN)
        #    La verificación de la firma de un certificado X.509 se hace sobre claves
        #    que soporten algoritmos de firma estándar como RSA o ECDSA.
        #    Para este caso, nos aseguramos de que es una clave RSA.
        if not isinstance(ca_public_key, rsa.RSAPublicKey):
            print("Error: La clave pública de la CA no es de tipo RSA.")
            return False

        hash_algorithm = cert.signature_hash_algorithm

        # 2. Comprobamos que el algoritmo sea soportado (no sea None)
        if hash_algorithm is None:
            print(f"Error: El algoritmo de hash de la firma del certificado '{cert.subject}' no es soportado.")
            return False

        # 3. A partir de aquí, Pylance sabe que hash_algorithm es de tipo HashAlgorithm
        #    y la llamada a verify es segura.

        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hash_algorithm,  # Usamos la variable que ya hemos comprobado
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        # Es buena idea capturar otras posibles excepciones para depurar
        print(f"Error inesperado durante la verificación del emisor: {e}")
        return False


def verificar_firma(cert: x509.Certificate, datos: bytes, firma: bytes, algoritmo: str) -> bool:
    """
    Verifica la firma digital de los datos utilizando la clave pública del certificado proporcionado.
    ... (resto del docstring) ...
    """

    # 1. Extraemos la clave pública del certificado.
    #    En este punto, su tipo es genérico (puede ser RSA, EC, etc.)
    public_key = cert.public_key()

    # 2. COMPROBACIÓN DE TIPO (LA SOLUCIÓN)
    #    Verificamos que la clave pública es del tipo que esperamos (RSA)
    #    para poder usar el método .verify() con los argumentos de padding.
    if not isinstance(public_key, rsa.RSAPublicKey):
        # O podrías lanzar un TypeError, pero devolver False es coherente con el diseño de tu función.
        print("Error: La clave pública del certificado no es de tipo RSA.")
        return False

    # 3. A partir de este punto, Pylance ya sabe que 'public_key' es una RSAPublicKey
    #    y que su método .verify() acepta los argumentos de padding y algoritmo.
    #    El aviso de "UnknownMemberType" desaparecerá.

    if algoritmo == "RSASSA-PSS-SHA256":
        pad_scheme = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )
        hash_alg = hashes.SHA256()
    elif algoritmo == "RSASSA-PKCS1v15-SHA256":
        pad_scheme = padding.PKCS1v15()
        hash_alg = hashes.SHA256()
    else:
        raise ValueError(f"Algoritmo no soportado: {algoritmo}")

    try:
        # Ahora Pylance está contento con esta llamada
        public_key.verify(firma, datos, pad_scheme, hash_alg)
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    pass
