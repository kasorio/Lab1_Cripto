import sys
from scapy.all import *

# Basado en codigo extraido de chatgpt
def cifrar_cesar(texto, corrimiento):
    texto_cifrado = ''
    for caracter in texto:
        if caracter.isalpha():
            Letra = ord(caracter)
            # se utiliza un deribado de la formula utilizada en ayudantia para el cifrado cesar.
            if caracter.isupper():
                Letra_cifrada = (((Letra - 65) + corrimiento) % 26 ) + 65
            else:
                Letra_cifrada = (((Letra - 97) + corrimiento) % 26 ) + 97
            texto_cifrado += chr(Letra_cifrada)
        else:
            texto_cifrado += caracter
    return texto_cifrado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(1)
    
    texto_original = sys.argv[1]
    corrimiento = int(sys.argv[2])
    texto_cifrado = cifrar_cesar(texto_original, corrimiento)

    print("Texto cifrado:", texto_cifrado)
