
from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# (A realizar por el alumno/a...)
KAT = open("KAT.bin", "rb").read()
# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################

# (A realizar por el alumno/a...)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket.conectar()

# Crea el nonce para enviarselo a Trent
nonce_alice_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_AT = []
msg_AT.append("Alice")
msg_AT.append(nonce_alice_origen.hex())
json_AT = json.dumps(msg_AT)
print("3: Alice envía: A -> T (descifrado): " + json_AT)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KAT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_AT.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)

# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################
# (A realizar por el alumno/a...)
print("Esperando las claves de Trent...")
cifrado = socket.recibir()
cifrado_mac= socket.recibir()
cifrado_nonce = socket.recibir()

#DESCIFRAMOS LOS DATOS
descifrado = funciones_aes.descifrarAES_GCM(KAT, cifrado_nonce, cifrado, cifrado_mac)

#Decodificar el contenido
json_TA = descifrado.decode("utf-8" ,"ignore")
print("4: Alice recibe de Trent: T->A (descifrado): " + json_TA)
msg_TA = json.loads(json_TA)
k1_HEX, k2_HEX, t_n_recibido_HEX = msg_TA
k1 = bytearray.fromhex(k1_HEX)
k2 = bytearray.fromhex(k2_HEX)
t_n_recibido = bytearray.fromhex(t_n_recibido_HEX)
print ("k1: " + k1_HEX + " k2: " + k2_HEX + " nonce: " + t_n_recibido_HEX)

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket.cerrar() 
if(nonce_alice_origen == t_n_recibido):
	print("El nonce recibido es correcto.")
else:
	print("El nonce recibido de Trent no coincide con el enviado")
	print("nonce_alice_origen " + nonce_alice_origen.hex())
	print("t_n_recibido " + t_n_recibido.hex())
	exit(1)
# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################
# (A realizar por el alumno/a...)
mensaje = "Juan Carlos"
print("Nombre enviado: " + mensaje)
cipher, nonce = funciones_aes.iniciarAES_CTR_cifrado(k1)
mensaje_cifrado = funciones_aes.cifrarAES_CTR(cipher, mensaje.encode('utf-8'))

hsend = HMAC.new(k2, mensaje_cifrado, digestmod=SHA256)
hmac_enviado= hsend.digest()

msg_AB = []
msg_AB.append(mensaje_cifrado.hex())
msg_AB.append(nonce.hex())
msg_AB.append(hmac_enviado.hex())
json_AB = json.dumps(msg_AB)
print("5: Alice envía: A -> B: " + json_AB)

socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5553)
socket.conectar()
socket.enviar(json_AB.encode("utf-8"))

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

# (A realizar por el alumno/a...)

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

# (A realizar por el alumno/a...)
