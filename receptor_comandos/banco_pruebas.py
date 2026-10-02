"""
Banco de pruebas automático de la práctica. NO NECESITAS MODIFICAR ESTO.

Lanza una batería de escenarios (mensaje válido y varios tipos de ataque) contra
`validar_mensaje_firmado()` para comprobar si la implementación del alumno es correcta.
"""
import os
import sys

# --- Bloque de importación robusto (SE PROPORCIONA) ---
directorio_script = os.path.dirname(os.path.abspath(__file__))
ruta_raiz_proyecto = os.path.dirname(directorio_script)
if ruta_raiz_proyecto not in sys.path:
    sys.path.insert(0, ruta_raiz_proyecto)

# --- Importaciones del trabajo del alumno y del simulador (SE PROPORCIONA) ---
from verifica_orden_alumno import validar_mensaje_firmado  # noqa: E402
from emisor_comandos.emite_comando import generar_json_firmado  # noqa: E402


def ejecutar_banco_pruebas() -> None:
    """Ejecuta todos los escenarios de prueba e imprime el resultado de cada uno."""
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

    mensaje_valido_original = b""
    resultados: list[tuple[str, str]] = []  # (descripcion, "superado" | "fallido" | "omitido")

    # Bucle que ejecuta cada escenario
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

        test_superado = es_valido == resultado_esperado
        resultados.append((descripcion, "superado" if test_superado else "fallido"))

        if test_superado:
            print("✅ ¡Prueba superada!")
        else:
            print("❌ ¡Prueba fallida! El validador no se comportó como se esperaba.")
            print(f"   Motivo del rechazo: {motivo}")

        # El resto de escenarios son ataques que SIEMPRE deben ser rechazados.
        # Si tu validador aún no hace nada (o rechaza todo sin motivo real),
        # superaría esas pruebas "por accidente" sin que tu implementación sea
        # correcta. Por eso, si el escenario base ("Mensaje Válido") no se
        # supera, no tiene sentido seguir: se detiene aquí el resto de pruebas.
        if descripcion == "Mensaje Válido" and not test_superado:
            print("\n⚠️  El escenario 'Mensaje Válido' no se ha superado, así que se "
                  "omite el resto de pruebas: sin un mensaje legítimo aceptado "
                  "correctamente, superar las pruebas de ataque no demuestra nada "
                  "(un validador que rechace siempre todo las superaría igualmente).")
            resultados.extend((otra_desc, "omitido") for otra_desc, _, _ in escenarios[1:])
            break

    # Resumen final: evita que mirar solo el último mensaje impreso lleve a
    # pensar que todo ha ido bien cuando en realidad algún test anterior falló
    # (u otros ni siquiera se han llegado a evaluar).
    num_superados = sum(1 for _, estado in resultados if estado == "superado")
    num_omitidos = sum(1 for _, estado in resultados if estado == "omitido")
    num_total = len(resultados)
    print(f"\n\n{'='*25}\n[RESUMEN] {num_superados}/{num_total} tests superados"
          f"{f' ({num_omitidos} omitidos)' if num_omitidos else ''}\n{'='*25}")

    if num_superados == num_total:
        print("✅ ¡TODOS LOS TESTS SUPERADOS!")
    else:
        fallidos = [descripcion for descripcion, estado in resultados if estado == "fallido"]
        omitidos = [descripcion for descripcion, estado in resultados if estado == "omitido"]
        if fallidos:
            print(f"❌ {len(fallidos)} TEST(S) FALLIDO(S): {', '.join(fallidos)}")
        if omitidos:
            print(f"⚠️  {len(omitidos)} TEST(S) OMITIDO(S) (no evaluados): {', '.join(omitidos)}")


if __name__ == "__main__":
    ejecutar_banco_pruebas()
