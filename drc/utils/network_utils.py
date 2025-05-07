# utils/network_utils.py

import socket

def get_local_subnet():
    """
    Возвращает подсеть в формате 'X.Y.Z.0/24' по текущему IP интерфейса.
    """
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
