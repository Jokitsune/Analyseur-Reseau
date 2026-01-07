# Pour les Découverte d’hôtes
from scapy.all import ARP, Ether, srp
import netifaces

def get_local_network():
    iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    netmask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']

    # Construction du réseau CIDR
    ip_parts = ip.split('.')
    netmask_parts = netmask.split('.')

    network = []
    for i in range(4):
        network.append(str(int(ip_parts[i]) & int(netmask_parts[i])))

    return '.'.join(network) + '/24'

def arp_scan(network=None):
    if network is None:
        network = get_local_network()

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    hosts = []
    for sent, received in result:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return hosts
