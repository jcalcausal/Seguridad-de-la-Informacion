from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util import Counter

#DATOS
BLOCK_SIZE_AES = 16 # Bloques de 128 bits en AES
key = get_random_bytes(16) # Clave aleatoria de 128 bits en AES
nonce = get_random_bytes(int(BLOCK_SIZE_AES/2))
data = "Hola Amigos de Seguridad".encode("utf-8")
print(data)

#Tamaño CONTADORES en bits: serían 8 bytes para el nonce y otros 8 para ir incrementando el contador

#CIFRADO
cipher = AES.new(key, AES.MODE_CTR, counter = Counter.new(64, prefix=nonce))
ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE_AES))
print(ciphertext)

#DESCIFRADO
decipher = AES.new(key, AES.MODE_CTR, counter = Counter.new(64, prefix=nonce))
new_text = unpad(decipher.decrypt(ciphertext), BLOCK_SIZE_AES).decode("utf-8", "ignore")
print(new_text)
