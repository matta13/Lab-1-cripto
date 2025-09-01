#!/usr/bin/env python3
from scapy.all import *
import sys, os

def enviar_icmp(texto, destino="google.com"):
    print("=== Ping real de referencia ===")
    os.system(f"ping -c 2 {destino}")

    print("\n=== Envío de paquetes ICMP personalizados ===")
    patron_final = b'!"#$%&\'()*+,-./01234567'  # 23 bytes

    for i, ch in enumerate(texto):
        # 1 char + 16 puntos + 23 de patrón = 40 bytes
        c = ch.encode('utf-8')[:1]
        payload = c + b"." * 16 + patron_final
        assert len(payload) == 40, f"Payload es {len(payload)} bytes en vez de 40"

        pkt = IP(dst=destino)/ICMP()/Raw(load=payload)
        print(f"\n[+] Enviando paquete {i+1} ('{ch}') con payload de {len(payload)} bytes")
        pkt.show()
        send(pkt, verbose=0)

    print("\n=== Paquetes ICMP enviados ===")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: sudo python3 {sys.argv[0]} '<texto_cifrado>'")
        sys.exit(1)
    enviar_icmp(sys.argv[1])


