import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import pbkfdf2hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

def generar_sal():
     return os.urandom(16) # sal aleatoria de 16 bytes, más segura que random
 
def derivar_clave(contrasena_maestra: str, sal: byres) -> bytes:
    kdf = pbkfdf2hmac(
        algorithm=hashes.SHA256(), # con qué herramienta interna trabajar  
        length=32, # longitud de la salida
        salt=sal, # conecta la sal con la contra
        iterations=480000, #contra + sal -> hash 1 -> resu1 | resu1 -> hash2 -> resu2 ... hasta el 480000
    )
    return kdf.derive(contrasena_maestra.encode("utf-8")) # asegurar que los caracteres especiales se usen bien
            
def cifrar