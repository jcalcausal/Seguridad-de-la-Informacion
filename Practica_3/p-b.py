

from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# Lee clave KBT
KBT = open("KBT.bin", "rb").read()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de conexion con T (5551)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()

# Crea el nonce para enviarselo a Trent
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Bob")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("1: Bob envía: B -> T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################
# (A realizar por el alumno/a...)
#Recibir el mensaje de Trent
print("Esperando las claves de Trent...")
cifrado2 = socket.recibir()
cifrado_mac2= socket.recibir()
cifrado_nonce2 = socket.recibir()

#DESCIFRAMOS LOS DATOS
descifrado = funciones_aes.descifrarAES_GCM(KBT, cifrado_nonce2, cifrado2, cifrado_mac2)

#Decodificar el contenido
json_BT = descifrado.decode("utf-8" ,"ignore")
print("2: Bob recibe de Trent: T->B (descifrado): " + json_BT)
msg_BT = json.loads(json_BT)
k1_HEX, k2_HEX, t_n_recibido_HEX = msg_BT
k1 = bytearray.fromhex(k1_HEX)
k2 = bytearray.fromhex(k2_HEX)
t_n_recibido = bytearray.fromhex(t_n_recibido_HEX)
print ("k1: " + k1_HEX + " k2: " + k2_HEX + " nonce: " + t_n_recibido_HEX)

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket.cerrar() 

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

# (A realizar por el alumno/a...)

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

# (A realizar por el alumno/a...)

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

# (A realizar por el alumno/a...)

