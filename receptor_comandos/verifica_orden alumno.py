import sys
import os
import json
import base64
from datetime import datetime, UTC, timedelta
from typing import Tuple

# cryptography debe estar instalado: pip install cryptography
from cryptography.x509.oid import NameOID  # Permite obtener campos del certificado

# --- Bloque de importación robusto (SE PROPORCIONA) ---
directorio_script = os.path.dirname(os.path.abspath(__file__))
ruta_raiz_proyecto = os.path.dirname(directorio_script)
if ruta_raiz_proyecto not in sys.path:
    sys.path.insert(0, ruta_raiz_proyecto)

# --- Importaciones de la librería del curso (SE PROPORCIONA) ---
from iia_lib import cripto  # noqa: E402


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


def check_autorizacion(certificado_emisor: cripto.x509.Certificate) -> bool:
    """
    CHEQUEO 5: El alumno debe implementar esta función.
    Debe comprobar si la identidad del emisor está en la lista de control de acceso (ACL).
    """
    print("\n--- [CHEQUEO 5/5] Comprobando Autorización (ACL)... ---")
    pass


def validar_mensaje_firmado(json_string_recibido: str) -> Tuple[bool, str]:
    """
    Función principal. El alumno debe implementar la cadena de validaciones.
    """

    return (False, "Función 'validar_mensaje_firmado' no implementada.")


if __name__ == "__main__":
    # --- BATERÍA DE PRUEBAS AUTOMÁTICA DEL ALUMNO ---
    from emisor_comandos.emite_comando import generar_json_firmado  # noqa: E402

    if os.path.exists("ids_procesados.txt"):
        os.remove("ids_procesados.txt")

    # Lista de escenarios a probar
    escenarios = [
        ("Mensaje Válido", None, True),
        ("Ataque de Repetición", None, False),
        ("Timestamp Antiguo", "timestamp_antiguo", False),
        ("Mensaje Manipulado", "mensaje_manipulado", False),
        ("Firma Corrupta", "firma_corrupta", False),
        ("Certificado No Confiable", "certificado_no_confiable", False),
    ]

    mensaje_valido_original = ""

    # Bucle que ejecuta cada escenario
    # ¡¡AQUÍ ESTABA EL ERROR CORREGIDO!! ('scenarios' -> 'escenarios')
    for descripcion, tipo_fallo, resultado_esperado in escenarios:
        print(f"\n\n{'='*25}\n[TEST] Ejecutando: {descripcion}\n{'='*25}")

        if descripcion == "Ataque de Repetición":
            mensaje_a_validar = mensaje_valido_original
            print("Re-enviando el primer mensaje válido para simular un ataque de repetición...")
        else:
            mensaje_a_validar = generar_json_firmado(tipo_fallo=tipo_fallo)

        if descripcion == "Mensaje Válido":
            mensaje_valido_original = mensaje_a_validar

        es_valido, motivo = validar_mensaje_firmado(mensaje_a_validar)

        print(f"\n--- RESULTADO DEL TEST: {descripcion} ---")
        print(f"Resultado esperado: {'VÁLIDO' if resultado_esperado else 'RECHAZADO'}")
        print(f"Resultado obtenido: {'VÁLIDO' if es_valido else 'RECHAZADO'}")

        if es_valido == resultado_esperado:
            print("✅ ¡Prueba superada!")
        else:
            print("❌ ¡Prueba fallida! El validador no se comportó como se esperaba.")
            print(f"   Motivo del rechazo: {motivo}")
