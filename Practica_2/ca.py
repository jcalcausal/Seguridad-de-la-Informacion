import funciones_rsa

alice_key = funciones_rsa.crear_RSAKey()
alice_pub_key = funciones_rsa.crear_RSAKey()
bob_key = funciones_rsa.crear_RSAKey()
bob_pub_key = funciones_rsa.crear_RSAKey()

funciones_rsa.guardar_RSAKey_Privada("alice_key.txt", alice_key, "Alice")
funciones_rsa.guardar_RSAKey_Privada("bob_key.txt", bob_key, "Bob")
funciones_rsa.guardar_RSAKey_Publica("alice_pub_key.txt", alice_pub_key)
funciones_rsa.guardar_RSAKey_Publica("bob_pub_key.txt", bob_pub_key)