

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
cifrado = socket.recibir()
cifrado_mac= socket.recibir()
cifrado_nonce = socket.recibir()

#DESCIFRAMOS LOS DATOS
descifrado = funciones_aes.descifrarAES_GCM(KBT, cifrado_nonce, cifrado, cifrado_mac)

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
print("Creando conexion con A y esperando su mensaje...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5553)
socket.escuchar()
cifrado = socket.recibir()

json_AB = cifrado.decode("utf-8", "ignore")
print("5: Bob recibe de Alice: A->B (mensaje cifrado, nonce, hmac): " + json_AB)
msg_AB = json.loads(json_AB)
mensaje_cifrado_HEX, nonce_HEX, hmac_HEX = msg_AB

mensaje_cifrado = bytearray.fromhex(mensaje_cifrado_HEX)
nonce = bytearray.fromhex(nonce_HEX)
hmac = bytearray.fromhex(hmac_HEX)

#Comprobamos que el HMAC recibido coincide con el del mensaje cifrado
hrecv = HMAC.new(k2, mensaje_cifrado, digestmod=SHA256)
try: 
	hrecv.verify(hmac)
	print("El HMAC recibido es correcto")
except ValueError:
	print("El HMAC recibido no coincide con el del mensaje recibido")
	exit(1)

decipher = funciones_aes.iniciarAES_CTR_descifrado(k1, nonce)
mensaje_descifrado = funciones_aes.descifrarAES_CTR(decipher, mensaje_cifrado).decode("utf-8", "ignore")
print ("Nombre recibido: " + mensaje_descifrado)

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################
# (A realizar por el alumno/a...)

mensaje = "Alcausa"
print("Apellido enviado: " + mensaje)
cipher, nonce = funciones_aes.iniciarAES_CTR_cifrado(k1)
mensaje_cifrado = funciones_aes.cifrarAES_CTR(cipher, mensaje.encode('utf-8'))

hsend = HMAC.new(k2, mensaje_cifrado, digestmod=SHA256)
hmac_enviado= hsend.digest()

msg_BA = []
msg_BA.append(mensaje_cifrado.hex())
msg_BA.append(nonce.hex())
msg_BA.append(hmac_enviado.hex())
json_BA = json.dumps(msg_BA)
print("6: Bob envía: B -> A: " + json_BA)

socket.enviar(json_BA.encode("utf-8"))

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################
# (A realizar por el alumno/a...)
cifrado = socket.recibir()

json_AB = cifrado.decode("utf-8", "ignore")
print("5: Bob recibe de Alice: A->B (mensaje cifrado, nonce, hmac): " + json_AB)
msg_AB = json.loads(json_AB)
mensaje_cifrado_HEX, nonce_HEX, hmac_HEX = msg_AB

mensaje_cifrado = bytearray.fromhex(mensaje_cifrado_HEX)
nonce = bytearray.fromhex(nonce_HEX)
hmac = bytearray.fromhex(hmac_HEX)

#Comprobamos que el HMAC recibido coincide con el del mensaje cifrado
hrecv = HMAC.new(k2, mensaje_cifrado, digestmod=SHA256)
try: 
	hrecv.verify(hmac)
	print("El HMAC recibido es correcto")
except ValueError:
	print("El HMAC recibido no coincide con el del mensaje recibido")
	exit(1)

decipher = funciones_aes.iniciarAES_CTR_descifrado(k1, nonce)
mensaje_descifrado = funciones_aes.descifrarAES_CTR(decipher, mensaje_cifrado).decode("utf-8", "ignore")
print ("Mensaje recibido: " + mensaje_descifrado)
if (mensaje_descifrado == "END"):
	print("Cerrado socket con A")
	socket.cerrar()
