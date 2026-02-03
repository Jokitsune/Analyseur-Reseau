from core.nmap_scan import nmap_discovery
from core.discovery import arp_scan, icmp_scan
from core.portscan import tcp_scan
import ipaddress


def menu_discovery():
    print("\n=== DÉCOUVERTE RÉSEAU ===")
    print("1. ARP Scan (local)")
    print("2. Ping Scan (ICMP)")
    print("3. IP unique")
    print("4. Actualiser le scan")
    print("0. Continuer vers l'analyse")
    return input("Votre choix : ")

def menu_actions():
    print("\n=== ANALYSEUR RÉSEAU ===")
    print("1. Scan de ports TCP")
    print("2. Banner grabbing")
    print("3. Analyse de vulnérabilités")
    print("4. Générer un rapport")
    print("0. Quitter")
    return input("Votre choix : ")

def discover_hosts():
    print("[*] Scan réseau automatique (ARP)...")
    hosts = arp_scan()

    if hosts:
        print("\n[+] Hôtes détectés :")
        for i, host in enumerate(hosts):
            print(f"{i+1}. {host['ip']} ({host['mac']})")
    else:
        print("[-] Aucun hôte détecté")

    while True:
        choice = menu_discovery()

        if choice == "1":
            hosts = arp_scan()

        elif choice == "2":
            network = input("Réseau (ex: 192.168.1.0/24) : ")

            try:
                ipaddress.ip_network(network)
            except ValueError:
                print("[-] Réseau invalide")
                continue

            hosts = icmp_scan(network)


        elif choice == "3":
            ip = input("Adresse IP : ")
            hosts = [{"ip": ip, "mac": "unknown"}]

        elif choice == "4":
            print("[*] Actualisation du scan...")
            hosts = arp_scan()


        elif choice == "5":
            network = input("Réseau (ex: 192.168.1.0/24) : ")
            hosts = nmap_discovery(network)


        elif choice == "0":
            break

        else:
            print("Choix invalide")
            continue

        print("\n[+] Hôtes détectés :")
        for i, host in enumerate(hosts):
            print(f"{i+1}. {host['ip']} ({host['mac']})")

    return hosts

def main():
    hosts = discover_hosts()

    if not hosts:
        print("[-] Aucun hôte détecté")
        return

    while True:
        choice = menu_actions()

        if choice == "1":
            for host in hosts:
                print(f"\n[*] Scan des ports pour {host['ip']}")
                host["open_ports"] = tcp_scan(host["ip"])
                print(f"[+] Ports ouverts : {host['open_ports']}")

        elif choice == "0":
            print("Bye 👋")
            break

if __name__ == "__main__":
    main()
