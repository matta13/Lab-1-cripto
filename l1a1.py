def cifrado_cesar(texto: str, corrimiento: int) -> str:
    resultado = ""
    for char in texto:
        if char.isalpha() and char.islower():  # Solo letras minúsculas
            resultado += chr((ord(char) - ord('a') + corrimiento) % 26 + ord('a'))
        else:
            resultado += char  # Si no es minúscula, lo dejamos igual
    return resultado

if __name__ == "__main__":
    texto = input("Ingrese el texto en minúsculas a cifrar: ")
    corrimiento = int(input("Ingrese el corrimiento: "))
    print("Texto cifrado:", cifrado_cesar(texto, corrimiento))
