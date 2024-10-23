import funciones_rsa
import funciones_aes
from socket_class import *
from Crypto.Random import get_random_bytes

alice_key = funciones_rsa.cargar_RSAKey_Privada("alice_key.txt", "Alice")
bob_pub_key = funciones_rsa.cargar_RSAKey_Publica("bob_pub_key.txt")

k1 = get_random_bytes(16)

#CIFRADO
cifrado = funciones_rsa.cifrarRSA_OAEP(k1, bob_pub_key)
firmado = funciones_rsa.firmarRSA_PSS(cifrado, alice_key)

#INICIAR SOCKET CLIENTE
socket_client = SOCKET_SIMPLE_TCP('127.0.0.1', 5511)
socket_client.conectar()

#ENVIAR EJERCICIO 1
socket_client.enviar(cifrado)
socket_client.enviar(firmado)

#EJERCICIO 2.b
IV = socket_client.recibir()
cifrado2 = socket_client.recibir()
firmado2 = socket_client.recibir()
try:
	funciones_rsa.comprobarRSA_PSS(cifrado2, firmado2, bob_pub_key)
	decipher = funciones_aes.iniciarAES_CTR_descifrado(k1, IV)
	descifrado2 = funciones_aes.descifrarAES_CTR(decipher, cifrado2).decode("utf-8")
	print(descifrado2)
except(ValueError, TypeError):
	print("Error en la verificación de la firma")

#EJERCICIO 2.C

cipher, IV2 = funciones_aes.iniciarAES_CTR_cifrado(k1)
mensaje = "Hola Bob".encode("utf-8")
cifrado3 = funciones_aes.cifrarAES_CTR(cipher, mensaje)
firmado3 = funciones_rsa.firmarRSA_PSS(cifrado3, alice_key)
socket_client.enviar(IV2)
socket_client.enviar(cifrado3)
socket_client.enviar(firmado3)

#CERRAR SOCKET CLIENTE
socket_client.cerrar()
