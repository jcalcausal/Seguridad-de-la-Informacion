from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes

# Paso 0: Crea las claves que T comparte con B y A
##################################################

# Crear Clave KAT, guardar a fichero
KAT = funciones_aes.crear_AESKey()
FAT = open("KAT.bin", "wb")
FAT.write(KAT)
FAT.close()

# Crear Clave KBT, guardar a fichero
KBT = funciones_aes.crear_AESKey()
FBT = open("KBT.bin", "wb")
FBT.write(KBT)
FBT.close()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de escucha de Bob (5551)
print("Esperando a Bob...")
socket_Bob = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket_Bob.escuchar()

# Crea la respuesta para B y A: K1 y K2
K1 = funciones_aes.crear_AESKey()
K2 = funciones_aes.crear_AESKey()

# Recibe el mensaje 1 de Bob, el cifrado, el mac y el nonce que produce AES_GCM
cifrado = socket_Bob.recibir()
cifrado_mac = socket_Bob.recibir()
cifrado_nonce = socket_Bob.recibir()

# Descifro los datos con AES GCM
datos_descifrado_ET = funciones_aes.descifrarAES_GCM(KBT, cifrado_nonce, cifrado, cifrado_mac)

# Decodifica el contenido: Bob, Nb
json_ET = datos_descifrado_ET.decode("utf-8" ,"ignore") # Antes de enviar codificamos el JSON, hay q decodificarlo
print("1: Trent recibe: B->T (descifrado): " + json_ET)
msg_ET = json.loads(json_ET) # Recupera el array Python a partir del JSON

# Extraigo el contenido
t_bob, t_nb = msg_ET
t_nb = bytearray.fromhex(t_nb)

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################

# (A realizar por el alumno/a...)
#Crear mensaje para mandar a Bob:
print ("K1: " + K1.hex() + " K2: " + K2.hex() + " nonce: " + t_nb.hex())
msg_BT = []
msg_BT.append(K1.hex())
msg_BT.append(K2.hex())
msg_BT.append(t_nb.hex())
json_BT = json.dumps(msg_BT)
print("2: Tren envía a Bob: T->B (Mensaje a enviar, descifrado): " + json_BT)

#Ciframos el mensaje a enviar
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_BT.encode("utf-8"))

#Enviar datos a Bob
socket_Bob.enviar(cifrado)
socket_Bob.enviar(cifrado_mac)
socket_Bob.enviar(cifrado_nonce)

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket_Bob.cerrar() 

# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################
# (A realizar por el alumno/a...)

print("Esperando a Alice...")
socket_Alice = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket_Alice.escuchar()

# Recibe el mensaje 3 de Alice, el cifrado, el mac y el nonce que produce AES_GCM
cifrado = socket_Alice.recibir()
cifrado_mac = socket_Alice.recibir()
cifrado_nonce = socket_Alice.recibir()

# Descifro los datos con AES GCM
datos_descifrado_AT = funciones_aes.descifrarAES_GCM(KAT, cifrado_nonce, cifrado, cifrado_mac)

# Decodifica el contenido: Alice, nonce_alice
json_AT = datos_descifrado_AT.decode("utf-8" ,"ignore") # Antes de enviar codificamos el JSON, hay q decodificarlo
print("3: Trent recibe: A->T (descifrado): " + json_AT)
msg_AT = json.loads(json_AT) # Recupera el array Python a partir del JSON

# Extraigo el contenido
t_alice, t_na = msg_AT
t_na = bytearray.fromhex(t_na)

# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################
# (A realizar por el alumno/a...)
# El mensaje a enviar a Alice es igual que el que enviamos a Bob, solo hay que cambiar el nonce
 
msg_TA = []
msg_TA.append(K1.hex())
msg_TA.append(K2.hex())
msg_TA.append(t_na.hex())
json_TA = json.dumps(msg_TA)
print("4: Tren envía a Alice: T->A (Mensaje a enviar, descifrado): " + json_TA)

#Ciframos el mensaje a enviar
aes_engine = funciones_aes.iniciarAES_GCM(KAT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_TA.encode("utf-8"))

#Enviar datos a Alice
socket_Alice.enviar(cifrado)
socket_Alice.enviar(cifrado_mac)
socket_Alice.enviar(cifrado_nonce)

# Cerramos el socket entre A y T, no lo utilizaremos mas
socket_Alice.cerrar() 