import funciones_rsa
import funciones_aes
from socket_class import *
from Crypto.Random import get_random_bytes

bob_key = funciones_rsa.cargar_RSAKey_Privada("bob_key.txt", "Bob")
alice_pub_key = funciones_rsa.cargar_RSAKey_Publica("alice_pub_key.txt")

#INICIAR SOCKET SERVIDOR
socket_servidor = SOCKET_SIMPLE_TCP('127.0.0.1', 5511)
socket_servidor.escuchar()

#RECIBIR SOCKET SERVIDOR
cifrado = socket_servidor.recibir()
firmado = socket_servidor.recibir()

#DESCIFRAR Y VERIFICAR FIRMA
descifrado = funciones_rsa.descifrarRSA_OAEP(cifrado, bob_key)
print(descifrado)
try:
	funciones_rsa.comprobarRSA_PSS(cifrado, firmado, alice_pub_key)
	print("Verificación de la firma correcta")
except(ValueError, TypeError):
	print("Verificación incorrecta de la firma")

#CERRAR SOCKET SERVIDOR
socket_servidor.cerrar()
