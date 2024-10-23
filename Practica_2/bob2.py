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
k1 = funciones_rsa.descifrarRSA_OAEP(cifrado, bob_key)
print(k1)
try:
	funciones_rsa.comprobarRSA_PSS(cifrado, firmado, alice_pub_key)
	print("Verificación de la firma correcta")
except(ValueError, TypeError):
	print("Verificación incorrecta de la firma")

#EJERCICIO 2.b
cipher, IV = funciones_aes.iniciarAES_CTR_cifrado(k1)
mensaje = "Hola Alice".encode("utf-8")
cifrado2 = funciones_aes.cifrarAES_CTR(cipher, mensaje)
firmado2 = funciones_rsa.firmarRSA_PSS(cifrado2, bob_key)
socket_servidor.enviar(IV)
socket_servidor.enviar(cifrado2)
socket_servidor.enviar(firmado2)

#EJERCICIO 2.c
IV2 = socket_servidor.recibir()
cifrado3 = socket_servidor.recibir()
firmado3 = socket_servidor.recibir()
try:
	funciones_rsa.comprobarRSA_PSS(cifrado3, firmado3, alice_pub_key)
	decipher = funciones_aes.iniciarAES_CTR_descifrado(k1, IV2)
	descifrado = funciones_aes.descifrarAES_CTR(decipher, cifrado3).decode("utf-8")
	print(descifrado)
except(ValueError, TypeError):
	print("Error al verificar la firma")

#CERRAR SOCKET SERVIDOR
socket_servidor.cerrar()
