from funciones_rsa import *

alice_key_aux = crear_RSAKey()
bob_key_aux = crear_RSAKey()

guardar_RSAKey_Privada("alice_key.txt", alice_key_aux, "Alice")
guardar_RSAKey_Privada("bob_key.txt", bob_key_aux, "Bob")
guardar_RSAKey_Publica("alice_pub_key.txt", alice_key_aux)
guardar_RSAKey_Publica("bob_pub_key.txt", bob_key_aux)