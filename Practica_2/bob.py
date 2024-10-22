import funciones_rsa
import funciones_aes
from socket_class import *
from Crypto.Random import get_random_bytes

bob_key = funciones_rsa.cargar_RSAKey_Privada("bob_key.txt")
alice_pub_key = funciones_rsa.cargar_RSAKey_Publica("alice_pub_key.txt")

#SOCKET SERVIDOR
socket_servidor = SOCKET_SIMPLE_TCP("127.0.0.1", 1337)
socket_servidor.escuchar()
cifrado = socket_servidor.recibir()
firmado = socket_servidor.recibir()

