import nmap

def nmap_discovery(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')

    hosts = []
    for host in nm.all_hosts():
        hosts.append({
            "ip": host,
            "mac": nm[host]['addresses'].get('mac', 'unknown'),
            "state": nm[host].state()
        })
    return hosts
