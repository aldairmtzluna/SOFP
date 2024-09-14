from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

def generate_key():
    return os.urandom(32)  # Genera una clave de 256 bits

def encrypt_value(value, key):
    # Genera un IV (vector de inicialización) aleatorio
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Añadir padding al valor para que su longitud sea múltiplo de 16
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(value.encode()) + padder.finalize()

    # Cifra el valor
    encrypted_value = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_value).decode('utf-8')

def decrypt_value(encrypted_value, key):
    # Decodifica el valor cifrado y separa el IV del valor cifrado
    encrypted_value = base64.b64decode(encrypted_value.encode('utf-8'))
    iv = encrypted_value[:16]
    encrypted_value = encrypted_value[16:]

    # Descifra el valor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_value = decryptor.update(encrypted_value) + decryptor.finalize()

    # Elimina el padding del valor descifrado
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_value = unpadder.update(decrypted_padded_value) + unpadder.finalize()
    return decrypted_value.decode('utf-8')