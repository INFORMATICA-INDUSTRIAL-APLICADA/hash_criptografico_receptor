import sys
import os
import json
import base64
from datetime import datetime, UTC, timedelta
from typing import Tuple

# cryptography debe estar instalado: pip install cryptography

# --- Bloque de importación robusto (SE PROPORCIONA) ---
directorio_script = os.path.dirname(os.path.abspath(__file__))
ruta_raiz_proyecto = os.path.dirname(directorio_script)
if ruta_raiz_proyecto not in sys.path:
    sys.path.insert(0, ruta_raiz_proyecto)

# --- Importaciones de la librería del curso (SE PROPORCIONA) ---
from iia_lib import cripto  # noqa: E402

# --- Rutas a ficheros usados por los chequeos (SE PROPORCIONA) ---
# RUTA_IDS_PROCESADOS es relativa (no se ancla a ruta_raiz_proyecto) porque
# banco_pruebas.py borra ese mismo fichero usando esa misma ruta relativa al
# arrancar cada ejecución; debes lanzar siempre los tests desde la raíz del
# proyecto (ver sección 8 del README).
RUTA_IDS_PROCESADOS = "ids_procesados.txt"
RUTA_CA_CERT = os.path.join(ruta_raiz_proyecto, "certificados", "ca", "ca_cert.pem")
RUTA_ACL = os.path.join(ruta_raiz_proyecto, "lista_control_acceso.txt")


# =============================================================================
# ZONA DE TRABAJO DEL ALUMNO
# =============================================================================

def check_timestamp(timestamp_str: str | None, ventana_validez_segundos: int = 300) -> bool:
    """
    CHEQUEO 1: El alumno debe implementar esta función.
    Debe comprobar si el timestamp del mensaje es reciente y válido.
    """
    print("\n--- [CHEQUEO 1/5] Comprobando Frescura (Timestamp)... ---")
    pass


def check_id_unicidad(id_transaccion: str | None) -> bool:
    """
    CHEQUEO 2: El alumno debe implementar esta función.
    Debe comprobar si el ID de transacción es nuevo.
    """
    print("\n--- [CHEQUEO 2/5] Comprobando Unicidad (ID de Transacción)... ---")
    pass


def check_autenticidad_emisor(
    certificado_emisor: cripto.x509.Certificate,
    certificado_ca: cripto.x509.Certificate
) -> bool:
    """
    CHEQUEO 3: El alumno debe implementar esta función.
    Debe comprobar si el certificado del emisor fue firmado por nuestra CA de confianza.
    Pista: usa cripto.verificar_emisor().
    """
    print("\n--- [CHEQUEO 3/5] Comprobando Autenticidad del Emisor... ---")
    pass


def check_integridad_mensaje(
    certificado_emisor: cripto.x509.Certificate,
    payload_canonico: bytes,
    firma: bytes
) -> bool:
    """
    CHEQUEO 4: El alumno debe implementar esta función.
    Debe comprobar que la firma digital corresponde exactamente al payload recibido.
    Pista: usa cripto.verificar_firma(). Recuerda que payload_canonico debe
    reconstruirse exactamente como lo firmó el emisor (ver json.dumps con
    sort_keys=True y separators=(',', ':') en emite_comando.py).
    """
    print("\n--- [CHEQUEO 4/5] Comprobando Integridad del Mensaje... ---")
    pass


def check_autorizacion(certificado_emisor: cripto.x509.Certificate) -> bool:
    """
    CHEQUEO 5: El alumno debe implementar esta función.
    Debe comprobar si la identidad del emisor está en la lista de control de acceso (ACL).
    Pista: usa cripto.obtener_common_name() para extraer el CN del certificado.
    """
    print("\n--- [CHEQUEO 5/5] Comprobando Autorización (ACL)... ---")
    pass


def validar_mensaje_firmado(json_bytes_recibido: bytes) -> Tuple[bool, str]:
    """
    Función principal. El alumno debe implementar la cadena de validaciones.

    Antes de nada, debe procesar adecuadamente los bytes que le llegan: parsear
    json_bytes_recibido con json.loads() (admite bytes directamente) y extraer de ahí
    el payload, la firma_b64 y el certificado_pem.

    Después, debe invocar, en este orden, los 5 chequeos descritos en el README, deteniéndose
    y rechazando el mensaje en cuanto uno de ellos falle:
      - CHEQUEO 1/5: check_timestamp()
      - CHEQUEO 2/5: check_id_unicidad()
      - CHEQUEO 3/5: check_autenticidad_emisor()
      - CHEQUEO 4/5: check_integridad_mensaje()
      - CHEQUEO 5/5: check_autorizacion()
    """
    # TODO: 1. Parsear json_bytes_recibido (payload, firma_b64, certificado_pem).
    #          json.loads() admite bytes directamente, no hace falta decodificar a mano.
    # TODO: 2. Llamar a check_timestamp() y check_id_unicidad() sobre el payload.
    # TODO: 3. Cargar el certificado del emisor (cripto.bytes_a_certificado) y el de la
    #          CA (cripto.cargar_certificado) y llamar a check_autenticidad_emisor().
    # TODO: 4. Recrear el payload canonicalizado y llamar a check_integridad_mensaje().
    # TODO: 5. Llamar a check_autorizacion() con el certificado ya validado.

    return (False, "Función 'validar_mensaje_firmado' no implementada.")


# El banco de pruebas automático vive en receptor_comandos/banco_pruebas.py (SE
# PROPORCIONA, no lo modifiques) para no mezclar tu zona de trabajo con el código
# de evaluación. Esta llamada es solo un atajo de comodidad: te permite lanzar los
# tests ejecutando directamente este fichero, sin tener que acordarte del otro.
if __name__ == "__main__":
    from banco_pruebas import ejecutar_banco_pruebas  # noqa: E402
    ejecutar_banco_pruebas()
