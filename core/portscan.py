# Pour les Scan de ports

import socket

COMMON_PORTS = [
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    80,   # HTTP
    110,  # POP3
    139,  # NetBIOS
    143,  # IMAP
    443,  # HTTPS
    445,  # SMB
    3389  # RDP
]

def tcp_scan(ip, ports=COMMON_PORTS, timeout=0.5):
    """
    Scan TCP des ports d'une adresse IP
    :return: liste des ports ouverts
    """
    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            open_ports.append(port)
        except:
            pass
        finally:
            sock.close()

    return open_ports
