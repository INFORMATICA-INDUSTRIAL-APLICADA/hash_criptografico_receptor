# Práctica: Validación de Comandos Seguros con PKI
**Ingeniería Eléctrica - Seguridad en Sistemas de Control**

## 1. Contexto: La Importancia de la Confianza Digital

En el mundo de los sistemas industriales, la red eléctrica inteligente (Smart Grid), el Internet de las Cosas (IoT) y la automatización, los dispositivos se comunican constantemente enviando órdenes y recibiendo datos. Una orden maliciosa o alterada (ej. "ABRIR VÁLVULA CRÍTICA" o "DESCONECTAR RED ELÉCTRICA") puede tener consecuencias catastróficas.

En esta práctica, actuarás como el ingeniero responsable de programar el firmware de un sistema crítico. Tu misión es diseñar un **módulo de validación de seguridad** que reciba comandos en formato JSON y decida si son legítimos antes de ejecutarlos. Para ello, utilizaremos una Infraestructura de Clave Pública (PKI), la misma tecnología que asegura las conexiones web (HTTPS), las transacciones bancarias y las comunicaciones seguras en todo el mundo.

## 2. Objetivos de Aprendizaje

Al completar esta práctica, serás capaz de:
-   Entender los componentes de una PKI: Autoridad de Certificación (CA), certificados digitales y firmas.
-   Implementar una cadena de validación de seguridad robusta en Python.
-   Verificar la **autenticidad** de un emisor validando su certificado digital.
-   Verificar la **integridad** de un mensaje validando su firma digital.
-   Implementar defensas contra ataques comunes como los **ataques de repetición (Replay Attacks)**.
-   Separar los conceptos de **autenticación** (¿eres quien dices ser?) y **autorización** (¿tienes permiso para hacer esto?).

## 3. Estructura del Proyecto

Recibirás una estructura de carpetas con todo lo necesario para la simulación:

```
.
├── certificados/               # Certificados y claves para la simulación
│   ├── ca/
│   │   └── ca_cert.pem         # <-- CERTIFICADO RAÍZ. Tu única ancla de confianza.
│   ├── impostor/               # Credenciales de un simulador "malicioso"
│   └── simulador/              # Credenciales del simulador legítimo
├── emisor_comandos/            # El código del simulador que genera los mensajes.
│   └── emite_comando.py        # NO NECESITAS MODIFICAR ESTO.
├── iia_lib/                    # Librería de ayuda con funciones criptográficas ya hechas.
│   ├── cripto.py
│   └── ...
├── receptor_comandos/
│   └── verifica_orden_alumno.py # <-- ¡ESTE ES TU FICHERO DE TRABAJO PRINCIPAL!
└── lista_control_acceso.txt    # Define qué usuarios tienen permiso para enviar órdenes.
```

## 4. Tu Misión: Implementar el Validador

Debes completar el fichero `receptor_comandos/verifica_orden_alumno.py`. Este fichero ya contiene una estructura básica y un banco de pruebas automático. Tu trabajo es rellenar la lógica de las siguientes funciones para que todos los tests se superen con éxito:

-   `check_timestamp()`
-   `check_id_unicidad()`
-   `check_autorizacion()`
-   `validar_mensaje_firmado()`

La función `validar_mensaje_firmado` es el corazón de la práctica y debe ejecutar, en el orden correcto, la siguiente cadena de validaciones. Si un solo chequeo falla, todo el proceso debe detenerse y el mensaje debe ser rechazado.

#### La Cadena de Validación de Seguridad:

1.  **CHEQUEO 1: Frescura (Timestamp):** Verifica que el mensaje es reciente. Un sistema seguro y eficiente realiza las comprobaciones más "baratas" (en términos de cómputo) primero. Rechazar un mensaje antiguo es mucho más rápido que realizar operaciones criptográficas complejas.

2.  **CHEQUEO 2: Unicidad (ID de Transacción):** Asegura que el mensaje no es una copia de uno recibido anteriormente. Deberás llevar un registro de los IDs de transacción ya procesados.

3.  **CHEQUEO 3: Autenticidad del Emisor:** Confirma que el certificado del emisor fue firmado por nuestra CA de confianza (`ca_cert.pem`). Este paso establece que el emisor es quien dice ser, creando una **cadena de confianza**.

4.  **CHEQUEO 4: Integridad del Mensaje:** Valida que la firma digital corresponde al contenido exacto del `payload`. Esto te da la certeza matemática de que el mensaje no ha sido alterado desde que fue firmado. **Pista:** Para que la verificación funcione, debes recrear la versión del `payload` exactamente como la firmó el emisor (proceso conocido como canonicalización).

5.  **CHEQUEO 5: Autorización:** Una vez que sabes que el mensaje es auténtico e íntegro, queda una última pregunta: ¿tenía este emisor (identificado por el "Common Name" de su certificado) permiso para enviar órdenes? Deberás consultar la `lista_control_acceso.txt` para tomar la decisión final.

## 5. Cómo Probar tu Código

El fichero `verifica_orden_alumno.py` está diseñado para ser autoevaluable. Simplemente ejecútalo desde tu terminal.

1.  Abre una terminal y asegúrate de estar en la carpeta raíz del proyecto (`hash_criptografico_receptor`).
2.  Ejecuta el script:
    ```bash
    python receptor_comandos/verifica_orden_alumno.py
    ```
3.  El script lanzará una batería de pruebas que simulan diferentes escenarios, incluyendo un mensaje válido y varios tipos de ataques.

**Tu objetivo es implementar el código necesario hasta que todos los tests muestren el mensaje: `✅ ¡Prueba superada!`**
