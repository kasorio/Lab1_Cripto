import sys
import time
import random
from scapy.all import *

# modificacion de codigo obtenido del repositorio https://github.com/Chelosky-O/Lab1Cripto/blob/main/pingv1.py
def generate_icmp_packet(dest_ip, identification, sequence, identifier, current_time, hex_bytes):
    ip_packet = IP(dst=dest_ip, id=identification)
    icmp_packet = ICMP(id=identifier, seq=sequence) / Raw(load=current_time + hex_bytes)
    return ip_packet / icmp_packet

def main():
    if len(sys.argv) != 2:
        sys.exit(1)

    palabra = sys.argv[1]

    # se utiliza la ip de loopback
    dest_ip = "127.0.0.1"
    identification = random.randint(1, 100)
    sequence = 1
    identifier = random.randint(1, 100)

    for char in palabra:
        timestamp = int(time.time() * 10**9)
        datafield = char.encode() + b'\x00' * 7 + bytes(range(0x10, 0x38))

        packet = generate_icmp_packet(dest_ip, identification, sequence, identifier, timestamp.to_bytes(8, byteorder='big'), datafield)
        time.sleep(1)
        
        send(packet)
        
        identification += random.randint(100, 250)
        sequence += 1

if __name__ == "__main__":
    main()
