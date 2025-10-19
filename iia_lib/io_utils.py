import json
from typing import Any


def guardar_bytes(clave: bytes, nom_fichero: str) -> None:
    """
    Guarda una secuencia de bytes en un archivo.

    Parámetros:
        clave (bytes): Los datos en formato de bytes que se desean guardar.
        nom_fichero (str): La ruta y nombre del archivo donde se guardarán los bytes.

    Retorna:
        None
    """
    with open(nom_fichero, "wb") as f:
        f.write(clave)


def leer_bytes(ruta_fichero: str) -> bytes:
    """
    Reads the contents of a file as bytes.

    Args:
        ruta_fichero (str): The path to the file to be read.

    Returns:
        bytes: The contents of the file as a bytes object.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        IOError: If an I/O error occurs while reading the file.
    """
    with open(ruta_fichero, "rb") as f:
        return f.read()


def leer_json(nombre_fichero: str) -> dict[str, Any]:
    """
    Reads a JSON file and returns its contents as a dictionary.

    Args:
        nombre_fichero (str): The path to the JSON file to be read.

    Returns:
        dict[str, Any]: The contents of the JSON file as a dictionary.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        json.JSONDecodeError: If the file is not a valid JSON.
    """
    with open(nombre_fichero, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def almacenar_json(data: dict[str, Any], nombre_fichero: str, indent: int = 4) -> None:
    """
    Stores a dictionary as a JSON file.

    Args:
        data (dict[str, Any]): The dictionary to be stored in JSON format.
        nombre_fichero (str): The name of the file where the JSON data will be saved.
        indent (int, optional): Number of spaces for indentation in the JSON file. Defaults to 4.

    Returns:
        None
    """
    with open(nombre_fichero, "w") as f:
        json.dump(data, f, indent=indent)
