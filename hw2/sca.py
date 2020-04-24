from scapy.all import ARP, Ether, srp
import socket

def get_mac(target_ip):
    # IP Address for the destination
    # create ARP packet
    arp = ARP(pdst=target_ip)
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    # a list of clients, we will fill this in the upcoming loop
    clients = []

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    # print clients
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    mac_list = {}
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))
        mac_list[client['ip']] = client['mac']
    return mac_list

network = '.'.join(socket.gethostbyname(socket.gethostname()).split('.')[:-1]) + '.0/24'
print(network)
mac_list = get_mac(network)

