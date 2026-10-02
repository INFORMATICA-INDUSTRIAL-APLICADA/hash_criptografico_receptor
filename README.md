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
│   ├── cripto.py               # Certificados, firmas y verificación (ver funciones clave más abajo).
│   └── io_utils.py             # Lectura/escritura de bytes y JSON en disco.
├── receptor_comandos/
│   ├── verifica_orden_alumno.py # <-- ¡ESTE ES TU FICHERO DE TRABAJO PRINCIPAL!
│   └── banco_pruebas.py        # Batería de pruebas automática. NO NECESITAS MODIFICAR ESTO.
└── lista_control_acceso.txt    # Lista de control de acceso (ACL): un "Common Name" autorizado por línea.
```

> Nota: dentro de `emisor_comandos/` e `iia_lib/` verás también ficheros `__init__.py` (necesarios para que Python trate las carpetas como paquetes) y carpetas `__pycache__` generadas automáticamente. Puedes ignorarlos.

## 4. Formato del Mensaje Recibido

La función que debes completar, `validar_mensaje_firmado(json_bytes_recibido: bytes)`, recibe un **único argumento de tipo `bytes`**: el mensaje completo, codificado como texto JSON y ya convertido a bytes (tal y como llegaría realmente por una red, un socket o el cuerpo de una petición HTTP; en la práctica de sockets que viene a continuación de esta verás por qué). Lo primero que debes hacer dentro de la función es parsearlo con `json.loads()`, que admite tanto `str` como `bytes`/`bytearray` directamente (se asume codificación UTF-8), así que no hace falta decodificarlo tú mismo antes.

Ese JSON, una vez parseado, es siempre un diccionario con esta forma (ejemplo real generado por `emite_comando.py`):

```json
{
    "payload": {
        "accion": "CERRAR",
        "parametros": {
            "sector": "A-1",
            "intensidad_porcentaje": 45,
            "flujo_max_l_min": 29.91
        },
        "id_transaccion": "1e04d3a4-d3fa-4b72-b598-696651319a13",
        "timestamp_utc": "2026-10-02T08:55:21.277007+00:00"
    },
    "firma_b64": "dvlk84StAfTEvZxG5rvghn0RldbBnENkh...(base64, recortado)...",
    "certificado_pem": "-----BEGIN CERTIFICATE-----\nMIIDsjCCApqgAwIBAgIU...(recortado)...\n-----END CERTIFICATE-----\n"
}
```

Siempre tiene exactamente estas 3 claves de primer nivel:

| Clave | Tipo | ¿Qué es? |
|---|---|---|
| `payload` | `dict` | El comando en sí (la orden que se quiere ejecutar), **más los metadatos de seguridad** `id_transaccion` (UUID único por mensaje) y `timestamp_utc` (fecha/hora UTC en formato ISO 8601, la que debes validar en el CHEQUEO 1). El resto de campos (`accion`, `parametros`...) son específicos del dominio y no necesitas validarlos. |
| `firma_b64` | `str` | La firma digital (RSA-PSS con SHA-256) calculada sobre la versión **canonicalizada** de `payload`, codificada en Base64 para poder viajar dentro de un JSON. Decodifícala con `base64.b64decode()` antes de pasarla a `cripto.verificar_firma()`. |
| `certificado_pem` | `str` | El certificado X.509 del emisor, en formato de texto PEM. Conviértelo a un objeto `cripto.x509.Certificate` con `cripto.bytes_a_certificado(certificado_pem.encode("utf-8"))` antes de usarlo en los CHEQUEOS 3, 4 y 5. |

#### Sobre la canonicalización

Un algoritmo de firma digital como RSA-PSS no firma "un diccionario" ni "un JSON": firma una **secuencia concreta de bytes**. El problema es que un mismo diccionario Python (o el mismo documento JSON, conceptualmente) se puede serializar a bytes de muchísimas formas distintas sin que cambie su significado:

```python
payload = {"accion": "ABRIR", "id_transaccion": "abc-123"}

json.dumps(payload)
# '{"accion": "ABRIR", "id_transaccion": "abc-123"}'          <- con espacios tras ":" y ","

json.dumps(payload, indent=4)
# '{\n    "accion": "ABRIR",\n    "id_transaccion": "abc-123"\n}'   <- con saltos de línea e indentado

json.dumps({"id_transaccion": "abc-123", "accion": "ABRIR"})
# '{"id_transaccion": "abc-123", "accion": "ABRIR"}'          <- mismas claves, distinto orden

json.dumps(payload, sort_keys=True, separators=(',', ':'))
# '{"accion":"ABRIR","id_transaccion":"abc-123"}'             <- sin espacios y claves ordenadas
```

Las cuatro cadenas representan **exactamente la misma información**, pero son secuencias de bytes **distintas**. Si el emisor firma una de ellas y el receptor, al verificar, recalcula la firma sobre otra (por ejemplo, porque usó un orden de claves distinto o añadió espacios), la operación criptográfica de verificación fallará aunque el contenido del mensaje no se haya alterado en absoluto. No es un fallo de seguridad: es, literalmente, estar comparando la firma de un texto distinto.

**Canonicalizar** significa precisamente eso: acordar de antemano **una única forma determinista** de serializar los datos, para que emisor y receptor obtengan siempre la misma secuencia de bytes a partir del mismo contenido lógico. En esta práctica, la forma canónica acordada (ver `emisor_comandos/emite_comando.py`) es:

```python
payload_canonico = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
```

- `sort_keys=True`: ordena las claves alfabéticamente, eliminando la ambigüedad del orden en que Python (o cualquier otro lenguaje) construyó el diccionario.
- `separators=(',', ':')`: elimina los espacios en blanco que `json.dumps()` añade por defecto después de `,` y de `:` (su valor por defecto es `separators=(', ', ': ')`).
- `.encode('utf-8')`: convierte el `str` resultante en los `bytes` que realmente espera firmar/verificar `cripto.verificar_firma()`.

**Dos cosas importantes que no debes confundir:**

1.  El JSON completo que recibe `validar_mensaje_firmado()` (con `"payload"`, `"firma_b64"` y `"certificado_pem"`) se genera con `json.dumps(json_final, indent=4)` **solo por legibilidad** al transmitir el mensaje entero; esa indentación no afecta a la firma.
2.  Lo único que debes canonicalizar eres tú mismo, dentro de tu código: una vez extraído el diccionario `payload` del mensaje recibido, debes volver a serializarlo **exactamente** con `sort_keys=True, separators=(',', ':')` antes de pasárselo a `cripto.verificar_firma()`. Si usas `json.dumps(payload)` a secas (sin esos dos argumentos), obtendrás una cadena de bytes distinta a la que firmó el emisor y **todos los mensajes válidos serán rechazados** por error, aunque nadie los haya manipulado.

## 5. Funciones de Apoyo Disponibles (`iia_lib`)

Esta práctica **no pretende que te conviertas en un experto en criptografía**. Las operaciones matemáticas complejas (generar claves, firmar datos, verificar firmas, comprobar certificados...) ya están implementadas y probadas en `iia_lib/cripto.py`; tu trabajo consiste en saber **qué hace cada función y cuándo llamarla**, no en entender su funcionamiento matemático interno. Es perfectamente normal que términos como "RSA", "PSS" o "SHA-256" te resulten nuevos: de momento te basta con saber que son los nombres de algoritmos estándar de la industria (los mismos que usan HTTPS o la firma electrónica de documentos) para firmar y verificar datos. Si en el futuro cursas una asignatura de seguridad más avanzada, profundizarás en cómo funcionan por dentro.

Las funciones que vas a necesitar para implementar los chequeos son:

| Función | Qué hace | Dónde la usarás |
|---|---|---|
| `cripto.cargar_certificado(ruta_fichero: str)` → `x509.Certificate` | Lee un fichero `.pem` del disco y lo convierte en un objeto certificado que puedes inspeccionar y pasar a otras funciones. | Para cargar la CA de confianza desde `RUTA_CA_CERT`. |
| `cripto.bytes_a_certificado(cert_bytes: bytes)` → `x509.Certificate` | Hace lo mismo que la anterior, pero a partir de bytes que ya tienes en memoria (no de un fichero en disco). | Para convertir el campo `certificado_pem` del mensaje recibido en un objeto certificado. Recuerda convertir antes el `str` a `bytes`: `certificado_pem.encode('utf-8')`. |
| `cripto.verificar_emisor(cert, ca_cert)` → `bool` | Comprueba si `cert` fue emitido y firmado por `ca_cert`. `True` = certificado de confianza; `False` = no se puede confiar en él (podría ser un impostor). | CHEQUEO 3, dentro de `check_autenticidad_emisor()`. |
| `cripto.verificar_firma(cert, datos: bytes, firma: bytes, algoritmo: str)` → `bool` | Comprueba si `firma` es la firma digital válida de `datos`, generada con la clave privada correspondiente al certificado `cert`. | CHEQUEO 4, dentro de `check_integridad_mensaje()`. |
| `cripto.ALGORITMO_FIRMA_PSS` | Constante de texto (`"RSASSA-PSS-SHA256"`) con el nombre del algoritmo de firma usado por el simulador. | Pásala como argumento `algoritmo` a `verificar_firma()`. |
| `cripto.obtener_common_name(cert)` → `str` | Extrae el "Common Name" (el nombre identificativo del titular) del certificado `cert`. | CHEQUEO 5, dentro de `check_autorizacion()`, para saber qué identidad comprobar contra la ACL. |

> **¿Por qué dos funciones distintas para cargar un certificado?** Porque cada certificado llega desde un sitio distinto: el certificado de la **CA** vive como fichero en el disco del propio receptor (`certificados/ca/ca_cert.pem`, ya estaba ahí antes de recibir ningún mensaje), así que se carga con `cripto.cargar_certificado()`. El certificado del **emisor**, en cambio, no está en tu disco: viaja dentro del propio mensaje JSON, como el `str` del campo `certificado_pem`, así que primero tienes que convertirlo a `bytes` (`.encode('utf-8')`) y usar `cripto.bytes_a_certificado()` para obtener el objeto certificado a partir de esos bytes en memoria.

> `iia_lib/io_utils.py` también ofrece funciones de utilidad (`leer_bytes`, `leer_json`...), pero no las necesitas para esta práctica: `lista_control_acceso.txt` e `ids_procesados.txt` son ficheros de **texto plano** (no JSON), así que te bastan las operaciones básicas de fichero de Python (`open()`, `.readlines()`, `.write()`, etc.).

### Rutas a ficheros ya definidas (SE PROPORCIONA)

Construir rutas de fichero correctamente no es el objetivo de esta práctica, así que `verifica_orden_alumno.py` ya incluye 3 constantes con las rutas que vas a necesitar. Úsalas en vez de escribir las rutas "a mano": así tu código funciona igual sin importar desde qué directorio lo ejecutes.

| Constante | Valor | Para qué la usarás |
|---|---|---|
| `RUTA_CA_CERT` | Ruta absoluta a `certificados/ca/ca_cert.pem` | CHEQUEO 3: cárgala con `cripto.cargar_certificado(RUTA_CA_CERT)` para obtener el certificado de la CA de confianza. |
| `RUTA_ACL` | Ruta absoluta a `lista_control_acceso.txt` | CHEQUEO 5: ábrela para comprobar si el Common Name del emisor está autorizado. |
| `RUTA_IDS_PROCESADOS` | `"ids_procesados.txt"` (ruta relativa al directorio desde el que ejecutes el script) | CHEQUEO 2: úsala para leer y anotar los `id_transaccion` ya vistos. Es relativa a propósito: `banco_pruebas.py` borra ese mismo fichero con esa misma ruta relativa al arrancar, así que si la cambias por una ruta absoluta podrías desincronizarte con él si alguna vez ejecutas desde un directorio distinto a la raíz del proyecto. |

## 6. Tu Misión: Implementar el Validador



Debes completar el fichero `receptor_comandos/verifica_orden_alumno.py`. Este fichero ya contiene una estructura básica con las firmas de las funciones que debes implementar; la batería de pruebas automática que las evalúa vive aparte, en `receptor_comandos/banco_pruebas.py` (no necesitas modificarla). Tu trabajo es rellenar la lógica de las siguientes funciones para que todos los tests se superen con éxito:

-   `check_timestamp()`
-   `check_id_unicidad()`
-   `check_autenticidad_emisor()`
-   `check_integridad_mensaje()`
-   `check_autorizacion()`
-   `validar_mensaje_firmado()`

La función `validar_mensaje_firmado` es el corazón de la práctica y debe ejecutar, en el orden correcto, la siguiente cadena de validaciones. Si un solo chequeo falla, todo el proceso debe detenerse y el mensaje debe ser rechazado.

#### La Cadena de Validación de Seguridad:

1.  **CHEQUEO 1: Frescura (Timestamp):** Verifica que el mensaje es reciente. Un sistema seguro y eficiente realiza las comprobaciones más "baratas" (en términos de cómputo) primero. Rechazar un mensaje antiguo es mucho más rápido que realizar operaciones criptográficas complejas. Implementa esta lógica en `check_timestamp()`.

2.  **CHEQUEO 2: Unicidad (ID de Transacción):** Asegura que el mensaje no es una copia de uno recibido anteriormente. Deberás llevar un registro persistente (por ejemplo, en un fichero de texto) de los IDs de transacción ya procesados en `check_id_unicidad()`, usando la ruta ya definida `RUTA_IDS_PROCESADOS`. **Nota:** el propio banco de pruebas borra ese fichero al arrancar, así que tendrás siempre un registro limpio en cada ejecución.

3.  **CHEQUEO 3: Autenticidad del Emisor:** Confirma que el certificado del emisor fue firmado por nuestra CA de confianza (cargada desde `RUTA_CA_CERT`). Este paso establece que el emisor es quien dice ser, creando una **cadena de confianza**. Implementa esta lógica en `check_autenticidad_emisor()`. **Pista:** usa `cripto.bytes_a_certificado()` para cargar el certificado recibido y `cripto.verificar_emisor()` para comprobarlo contra la CA.

4.  **CHEQUEO 4: Integridad del Mensaje:** Valida que la firma digital corresponde al contenido exacto del `payload`. Esto te da la certeza matemática de que el mensaje no ha sido alterado desde que fue firmado. Implementa esta lógica en `check_integridad_mensaje()`. **Pista:** usa `cripto.verificar_firma()`, y recuerda que para que la verificación funcione debes recrear la versión del `payload` exactamente como la firmó el emisor (proceso conocido como canonicalización, ver cómo lo hace `emite_comando.py` con `json.dumps(..., sort_keys=True, separators=(',', ':'))`).

5.  **CHEQUEO 5: Autorización:** Una vez que sabes que el mensaje es auténtico e íntegro, queda una última pregunta: ¿tenía este emisor (identificado por el "Common Name" de su certificado, accesible vía `cripto.obtener_common_name()`) permiso para enviar órdenes? Implementa esta comprobación en `check_autorizacion()`, consultando `RUTA_ACL` (un Common Name autorizado por línea) para tomar la decisión final.

Las 5 funciones `check_...` solo comprueban una condición cada una; es `validar_mensaje_firmado()` quien debe parsear el JSON recibido, invocarlas en este orden exacto y combinar sus resultados en un único veredicto (aceptar o rechazar el mensaje).

## 7. Requisitos Previos

Esta práctica usa la librería [`cryptography`](https://cryptography.io/). Antes de ejecutar nada, instálala en tu entorno:

```bash
pip install cryptography
```

## 8. Cómo Probar tu Código

El fichero `banco_pruebas.py` se encarga de evaluar automáticamente tu implementación. Puedes lanzarlo de dos formas equivalentes:

1.  Abre una terminal y asegúrate de estar en la carpeta raíz del proyecto (`hash_criptografico_receptor_alumnos`).
2.  Ejecuta el banco de pruebas, directamente:
    ```bash
    python receptor_comandos/banco_pruebas.py
    ```
    o, por comodidad, ejecutando tu propio fichero de trabajo (que lo invoca automáticamente):
    ```bash
    python receptor_comandos/verifica_orden_alumno.py
    ```
3.  El script lanzará una batería de pruebas que simulan diferentes escenarios, incluyendo un mensaje válido y varios tipos de ataques.

Al final de la ejecución verás un bloque `[RESUMEN]` con el total de pruebas superadas. **No te fíes solo del último mensaje `✅ ¡Prueba superada!` de cada test individual** (si miras únicamente el último, podrías pensar que todo ha ido bien cuando en realidad algún test anterior falló): fíjate en ese resumen final.

> **Nota:** si el escenario base "Mensaje Válido" no se supera, el resto de pruebas de ataque se **omiten** en lugar de ejecutarse, porque no demuestran nada sin una implementación que primero acepte correctamente un mensaje legítimo (un validador que rechace todo pasaría esas pruebas "por accidente"). Verás esos tests marcados como "omitido" en el resumen en vez de como superados.

**Tu objetivo es implementar el código necesario hasta que el resumen final muestre: `✅ ¡TODOS LOS TESTS SUPERADOS!`**
