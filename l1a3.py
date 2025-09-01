#!/usr/bin/env python3
from scapy.all import *
import sys
import re
from wordfreq import zipf_frequency

# === Reconstrucción desde archivo pcapng ===
def reconstruir_desde_pcap(archivo):
    recibido = []
    try:
        paquetes = rdpcap(archivo)
    except Exception as e:
        print(f"[!] Error al abrir {archivo}: {e}")
        sys.exit(1)

    for pkt in paquetes:
        if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
            # Solo ICMP Echo Request (type=8)
            if pkt[ICMP].type == 8:
                data = pkt[Raw].load
                if len(data) == 40:
                    ch = data[:1].decode(errors="ignore")
                    recibido.append(ch)
    return "".join(recibido)

# === Cifrado César: probar todos los desplazamientos ===
def cesar_decrypt(ciphertext):
    resultados = []
    for shift in range(26):
        decrypted = []
        for ch in ciphertext:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                decrypted.append(chr((ord(ch) - base - shift) % 26 + base))
            else:
                decrypted.append(ch)
        resultados.append(("Desplazamiento " + str(shift), "".join(decrypted)))
    return resultados

# === Heurística basada en frecuencia de palabras reales ===
def detectar_mas_probable(resultados, idioma="es"):
    mejor_score = -1
    mejor_idx = 0

    for i, (_, texto) in enumerate(resultados):
        palabras = re.findall(r"[a-zA-Záéíóúüñ]+", texto.lower())
        score = 0

        for palabra in palabras:
            # zipf_frequency devuelve frecuencia logarítmica, >0 si es palabra real
            freq = zipf_frequency(palabra, idioma)
            if freq > 1.5:  # filtramos ruido
                score += freq

        if score > mejor_score:
            mejor_score = score
            mejor_idx = i

    return mejor_idx

# === Mostrar resultados en terminal con colores ===
def mostrar_resultados(resultados, idx_probable):
    VERDE = "\033[92m"
    RESET = "\033[0m"

    for i, (titulo, texto) in enumerate(resultados):
        if i == idx_probable:
            print(f"{VERDE}{titulo}: {texto}{RESET}")
        else:
            print(f"{titulo}: {texto}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: python3 {sys.argv[0]} captura.pcapng")
        sys.exit(1)

    archivo = sys.argv[1]
    mensaje = reconstruir_desde_pcap(archivo)

    print("\n=== Mensaje reconstruido ===")
    print(mensaje)

    resultados = cesar_decrypt(mensaje)
    idx_probable = detectar_mas_probable(resultados, idioma="es")  # o "en"

    print("\n=== Posibles descifrados ===")
    mostrar_resultados(resultados, idx_probable)

    print("\n=== Descifrado más probable ===")
    print(resultados[idx_probable][1])

