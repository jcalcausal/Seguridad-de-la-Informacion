from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util import Counter

#DATOS
BLOCK_SIZE_AES = 16 # Bloques de 128 bits en AES
key = get_random_bytes(16) # Clave aleatoria de 128 bits en AES
nonce = get_random_bytes(BLOCK_SIZE_AES) # Nonce del mismo tamaño del bloque
mac_len = 16 # Longitud de la etiqueta MAC
data = "Hola Amigos de Seguridad".encode("utf-8")
print(data)

#CIFRADO
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
ciphertext, tag = cipher.encrypt_and_digest(data)
print(ciphertext)
print(tag)

#DESCIFRADO
decipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
try:
	new_data = decipher.decrypt_and_verify(ciphertext, tag)
	print(new_data)
except ValueError:
	print("Fallo de autenticidad: los datos han sido modificados")