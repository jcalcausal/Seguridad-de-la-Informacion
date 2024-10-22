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

#SOCKET CLIENTE
socket_client = SOCKET_SIMPLE_TCP('127.0.0.1', 5511)
socket_client.conectar()
socket_client.enviar(cifrado)
socket_client.enviar(firmado)
socket_client.cerrar()
