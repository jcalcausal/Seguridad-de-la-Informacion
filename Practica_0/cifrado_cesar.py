def cifradoCesarAlfabetoInglesMAY(cadena, offset):
	"""Devuelve	un	cifrado	Cesar	tradicional	(+3)"""
	#	Definir	la nueva cadena resultado
	resultado = ''
	#	Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
	i = 0
	while i	< len(cadena):
		#	Recoge el caracter a cifrar
		ordenClaro = ord(cadena[i])
		ordenCifrado = 0
		#	Cambia	el	caracter a cifrar
		if (ordenClaro >= 65 and ordenClaro	<=	90):
			ordenCifrado = (((ordenClaro - 65) + offset) % 26) +	65
			# Añade el caracter cifrado al resultado
			resultado =	resultado +	chr(ordenCifrado)
		elif (ordenClaro >= 97 and ordenClaro	<=	122):
			ordenCifrado = (((ordenClaro - 97) + offset) % 26) +	97
			# Añade el caracter cifrado al resultado
			resultado =	resultado +	chr(ordenCifrado)
		else:
			# Si no es una letra lo deja igual
			resultado = resultado + cadena[i]
		i =	i +	1
	#	devuelve el resultado
	return resultado

def descifradoCesarAlfabetoInglesMAY(cadena, offset):
	"""Devuelve	un	cifrado	Cesar	tradicional	(+3)"""
	#	Definir	la nueva cadena resultado
	resultado = ''
	#	Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
	i = 0
	while i	< len(cadena):
		#	Recoge el caracter a cifrar
		ordenCifrado = ord(cadena[i])
		ordenClaro = 0
		#	Cambia	el	caracter a cifrar
		if (ordenCifrado >= 65 and ordenCifrado <= 90):
			ordenClaro = (((ordenCifrado - 65) - offset) % 26) + 65
			# Añade el caracter cifrado al resultado
			resultado =	resultado +	chr(ordenClaro)
		elif (ordenCifrado >= 97 and ordenCifrado <= 122):
			ordenClaro = (((ordenCifrado - 97) - offset) % 26) + 97
			# Añade el caracter cifrado al resultado
			resultado =	resultado +	chr(ordenClaro)
		else:
			# Si no es una letra lo deja igual
			resultado = resultado + cadena[i]
		i =	i +	1
	#	devuelve el resultado
	return resultado

claroCESARMAY = 'aRZ VENI VIDI VINCI AURIA'
print(claroCESARMAY)
cifradoCESARMAY = cifradoCesarAlfabetoInglesMAY(claroCESARMAY, 3)
print(cifradoCESARMAY)
print(descifradoCesarAlfabetoInglesMAY(cifradoCESARMAY, 3), 3)