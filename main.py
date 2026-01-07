
from core.discovery import arp_scan
from core.portscan import tcp_scan

def menu():
    print("\n=== ANALYSEUR RÉSEAU ===")
    print("1. Scan de ports TCP")
    print("2. Banner grabbing")
    print("3. Analyse de vulnérabilités")
    print("4. Générer un rapport")
    print("0. Quitter")

    return input("Votre choix : ")

def main():
    print("[*] Scan du réseau en cours...\n")
    hosts = arp_scan()

    if not hosts:
        print("[-] Aucun hôte détecté")
        return

    print("[+] Hôtes détectés :")
    for i, host in enumerate(hosts):
        print(f"{i+1}. {host['ip']} ({host['mac']})")

    while True:
        choice = menu()

        if choice == "1":
            for host in hosts:
                print(f"\n[*] Scan des ports pour {host['ip']}")
                ports = tcp_scan(host["ip"])
                host["open_ports"] = ports
                print(f"[+] Ports ouverts : {ports if ports else 'Aucun'}")

        elif choice == "0":
            print("Bye 👋")
            break

        else:
            print("Choix invalide")

if __name__ == "__main__":
    main()
