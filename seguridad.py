import hmac
import hashlib
import secrets

ALGORITMO_HASH = hashlib.sha512
LONGITUD_CLAVE = 64 # 512 bits
LONGITUD_NONCE = 16 # 128 bits
SALT_GLOBAL = b'f4a1d8b9c2e3f0a5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9'

def derivar_clave(password: str) -> bytes:
    """
    Transforma la contraseña en una clave criptográfica de longitud adecuada (512 bits).
    """
    return hashlib.pbkdf2_hmac(
        'sha512', 
        password.encode('utf-8'), 
        SALT_GLOBAL, 
        100000,
        dklen=LONGITUD_CLAVE
    )

def generar_nonce() -> str:
    """
    Genera un número aleatorio único en formato hexadecimal.
    """
    return secrets.token_hex(LONGITUD_NONCE)

def calcular_hmac(clave: bytes, mensaje: str, nonce: str) -> str:
    """
    Genera el código de autenticación (HMAC) usando la clave derivada.
    """
    payload = f"{mensaje}|{nonce}".encode('utf-8')
    firma = hmac.new(clave, payload, ALGORITMO_HASH).hexdigest()
    return firma

def crear_mensaje_seguro(clave: bytes, mensaje: str) -> str:
    nonce = generar_nonce()
    firma = calcular_hmac(clave, mensaje, nonce)
    return f"{mensaje}|{firma}|{nonce}"

def verificar_integridad(clave: bytes, mensaje_recibido: str, nonces_usados: set) -> tuple[bool, str, str]:
    try:
        partes = mensaje_recibido.rsplit('|', 2)
        if len(partes) != 3:
            return False, "", "ERROR. Formato de mensaje incorrecto"

        mensaje_real = partes[0]
        hmac_recibido = partes[1]
        nonce_recibido = partes[2]

        # CONTROL DE REPLAY
        if nonce_recibido in nonces_usados:
            return False, "", f"ERROR DE SEGURIDAD. Nonce reutilizado."
        
        nonces_usados.add(nonce_recibido)

        # VERIFICACIÓN HMAC
        hmac_calculado = calcular_hmac(clave, mensaje_real, nonce_recibido)

        if hmac.compare_digest(hmac_calculado, hmac_recibido): # COMPARE_DIGEST PARA EVITAR LOS ATAQUES DE CANAL LATERAL
            return True, mensaje_real, ""
        else:
            return False, "", "ERROR DE SEGURIDAD. La firma no coincide."
            
    except Exception as e:
        return False, "", f"Excepción en verificación: {e}"