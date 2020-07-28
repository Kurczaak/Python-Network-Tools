#!/usr/bin/env python

import scapy.layers.l2 as l2
from mac_vendor_lookup import MacLookup
import optparse
import re

TIMEOUT = 2

# get args from the command line and return them
def get_options():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--range", dest="range",
                      help="Specify the range of IPs to scan. Example: net_scanner -r 192.168.0.1/24")
    parser.add_option("-t", "--timeout", dest="timeout",
                      help="Specify the time to wait after the last packet has been sent in seconds. Default 2")
    (options, args) = parser.parse_args()
    return options


# check the user input
def check_options(options):
    ip_regex = "\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(/?\d{1,2})?"

    if not options.range and not options.timeout:
        print("Print -h for help")
        return False
    if not options.range:
        print("No --range parameter. You have to specify the range of IP addresses")
        return False
    if not re.fullmatch(ip_regex, options.range):
        print("Incorrectly specified IP range. Specify either a certain IP address or range of addresses.")
        return False
    if not options.timeout:
        options.timeout = TIMEOUT
        return True
    if not options.timeout.isdigit():
        print("The timeout needs to be a non-negative digit")
        return False
    return True


# function returns IPs and corresponding MACs for the given ip address
def scan_network(ip_address, timeout):
    arp_request = l2.ARP(pdst=ip_address)  # ARP request to get the MAC associated with the specified IP/ range of IPs
    ethernet_broadcast = l2.Ether(dst="ff:ff:ff:ff:ff:ff")  # send the request on the broadcast address
    broadcast_packet = ethernet_broadcast / arp_request  # making the arp_request on the broadcast channel packet
    answers = l2.srp(broadcast_packet, timeout=timeout, verbose=False)[0]  # store only answered packets
    return answers


# extract IPs and MACs from the answered ARP requests and return them as a list of dictionaries
def extract_devices(answered_packets):
    devices = []
    for answer in answered_packets:  # handle each answer separately
        device = {"ip": answer[1].psrc, "mac": answer[1].hwsrc}
        devices.append(device)
    return devices


def print_devices(devices):
    print("IP address\tMAC address\t\tVendor")
    for device in devices:
        print(device["ip"] + "\t" + device["mac"] + "\t" + MacLookup().lookup(device["mac"]))


opts = get_options()

if check_options(opts):  # if options have been specified correctly run the program
    ip_range = opts.range
    timeout = opts.timeout
    answered_packets = scan_network(ip_range, int(timeout))  # get the answered packets in the given ip range
    devices = extract_devices(answered_packets)  # extract devices information form the packets
    print_devices(devices)  # print the result to the user
