import sys
import os
import json
import base64
import uuid
from datetime import datetime, UTC, timedelta
import random
from typing import Any

# =============================================================================
# BLOQUE 1: CONFIGURACIÓN DE RUTAS
# =============================================================================
directorio_script = os.path.dirname(os.path.abspath(__file__))
ruta_raiz_proyecto = os.path.dirname(directorio_script)
if ruta_raiz_proyecto not in sys.path:
    sys.path.insert(0, ruta_raiz_proyecto)


# =============================================================================
# BLOQUE 2: IMPORTACIONES DE LIBRERÍA PROPIA
# =============================================================================
from iia_lib import cripto  # noqa: E402
from iia_lib import io_utils  # noqa: E402


# =============================================================================
# BLOQUE 3: LÓGICA DEL EMISOR
# =============================================================================

def comando_enriquecido(comando: dict[str, Any]) -> dict[str, Any]:
    """Toma un diccionario base y le añade metadatos únicos."""
    comando = comando.copy()
    id_transaccion = str(uuid.uuid4())
    timestamp_actual = datetime.now(UTC).isoformat()
    comando['id_transaccion'] = id_transaccion
    comando['timestamp_utc'] = timestamp_actual
    return comando


def generar_json_firmado(tipo_fallo: str | None = None) -> str:
    """
    Genera un comando aleatorio y lo firma.
    Puede introducir fallos a propósito para realizar pruebas.

    Args:
        tipo_fallo (str | None): El tipo de fallo a introducir.
            - None: Mensaje válido.
            - "timestamp_antiguo": El mensaje es demasiado viejo.
            - "mensaje_manipulado": El payload no coincide con la firma.
            - "certificado_no_confiable": El certificado es de una CA no reconocida.
            - "firma_corrupta": La firma es basura.
    """
    # --- Fase de preparación: Generar un mensaje válido como base ---
    # ... (El código para generar payload_base y payload_enriquecido es el mismo) ...
    payload_base = {
        "accion": random.choice(["ABRIR", "CERRAR"]),
        "parametros": {
            "sector": random.choice(["A-1", "B-2"]),
            "intensidad_porcentaje": random.randint(0, 100),
            "flujo_max_l_min": round(random.uniform(5.0, 75.0), 2)
        }
    }
    payload_enriquecido = comando_enriquecido(payload_base)

    # --- Cargar credenciales VÁLIDAS por defecto ---
    nombre_simulador = "Simulador_IoT_Aula_1"
    ruta_certificados = os.path.join(ruta_raiz_proyecto, "certificados", "simulador")
    ruta_clave_privada = os.path.join(ruta_certificados, f"{nombre_simulador}_private_key.pem")
    clave_privada_bytes = io_utils.leer_bytes(ruta_clave_privada)
    clave_privada_simulador = cripto.bytes_a_clave_privada(clave_privada_bytes)
    ruta_certificado = os.path.join(ruta_certificados, f"{nombre_simulador}_cert.pem")
    certificado_simulador_pem = io_utils.leer_bytes(ruta_certificado).decode('utf-8')

    # --- Introducir fallos específicos ---
    if tipo_fallo == "timestamp_antiguo":
        # Hacemos que el timestamp sea de hace 1 hora (más que los 5 min de validez)
        hora_antigua = datetime.now(UTC) - timedelta(hours=1)
        payload_enriquecido['timestamp_utc'] = hora_antigua.isoformat()

    if tipo_fallo == "certificado_no_confiable":
        # Usamos las credenciales del impostor que creamos antes
        print("[Simulador] Usando credenciales del IMPOSTOR...")
        ruta_impostor = os.path.join(ruta_raiz_proyecto, "certificados", "impostor")
        clave_falsa_bytes = io_utils.leer_bytes(os.path.join(ruta_impostor, "simulador_falso_private_key.pem"))
        clave_privada_simulador = cripto.bytes_a_clave_privada(clave_falsa_bytes)  # ¡Sobrescribe la clave!
        cert_falso_bytes = io_utils.leer_bytes(os.path.join(ruta_impostor, "simulador_falso_cert.pem"))
        certificado_simulador_pem = cert_falso_bytes.decode('utf-8')  # ¡Sobrescribe el cert!

    # --- Firmar el payload (que puede estar ya modificado) ---
    payload_json_string = json.dumps(payload_enriquecido, sort_keys=True, separators=(',', ':'))
    payload_bytes = payload_json_string.encode('utf-8')
    firma_bytes = cripto.firmar_datos(clave_privada_simulador, payload_bytes)
    firma_b64 = base64.b64encode(firma_bytes).decode('ascii')

    # --- Construir el paquete JSON ---
    json_final = {
        "payload": payload_enriquecido,
        "firma_b64": firma_b64,
        "certificado_pem": certificado_simulador_pem
    }

    # --- Introducir fallos POST-FIRMA ---
    if tipo_fallo == "mensaje_manipulado":
        # Cambiamos el payload DESPUÉS de haber calculado la firma
        json_final["payload"]["parametros"]["sector"] = "SECTOR_MODIFICADO"
        print("[Simulador] Mensaje MANIPULADO después de firmar.")

    if tipo_fallo == "firma_corrupta":
        json_final["firma_b64"] = "estoNOesUNAfirmaVALIDAenBASE64=="
        print("[Simulador] Firma REEMPLAZADA por basura.")

    return json.dumps(json_final, indent=4)


def evaluar_respuesta_alumno(json_original_str: str, id_recibido_del_alumno: str) -> str:
    """
    Compara el ID de transacción de un mensaje original con el que envía
    el alumno como prueba de que ha validado correctamente el mensaje.
    """
    try:
        mensaje_original = json.loads(json_original_str)
        id_correcto = mensaje_original["payload"]["id_transaccion"]

        if id_correcto == id_recibido_del_alumno:
            return f"✅ ¡CORRECTO! El ID de transacción '{id_correcto}' coincide. Has validado el mensaje con éxito."
        else:
            return f"❌ INCORRECTO. Se esperaba el ID '{id_correcto}' pero se recibió '{id_recibido_del_alumno}'. Revisa tu código de parsing."

    except (json.JSONDecodeError, KeyError):
        return "❌ ERROR DE EVALUACIÓN. El formato del JSON original parece estar corrupto."


# =============================================================================
# BLOQUE 4: PUNTO DE ENTRADA PARA PRUEBAS
# =============================================================================
if __name__ == "__main__":
    print("--- Generando un mensaje JSON firmado (plantilla realista) ---")
    mensaje_para_alumno = generar_json_firmado()
    print(mensaje_para_alumno)
