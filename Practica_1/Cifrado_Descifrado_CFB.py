from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util import Counter

#DATOS
BLOCK_SIZE_AES = 16 # Bloques de 128 bits en AES
key = get_random_bytes(16) # Clave aleatoria de 128 bits en AES
IV = get_random_bytes(16) # Vector de inicialización
data = "Hola Amigos de Seguridad".encode("utf-8")
print(data)

#CIFRADO
cipher = AES.new(key, AES.MODE_CFB, IV)
ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE_AES))
print(ciphertext)

#DESCIFRADO
decipher = AES.new(key, AES.MODE_CFB, IV)
new_text = unpad(decipher.decrypt(ciphertext), BLOCK_SIZE_AES).decode("utf-8", "ignore")
print(new_text)