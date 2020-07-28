#!/usr/bin/env python

import subprocess
import optparse
import re


def get_opts():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="The interface to change the MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="The MAC address to change to")
    (options, args) = parser.parse_args()
    return options


def check_opts(options):
    if not options.interface and not options.new_mac:
        print("Print -h or --help to see the manual")
        return False
    elif not options.interface:
        print("You need to specify the interface. Try using -i [interface_name] or --interface [interface_name]")
        return False
    elif not options.new_mac:
        print("You need to specify a new MAC. Try using -m [new_mac] or --mac [new_mac]")
        return False
    else:
        return True


def change_mac(interface, new_mac):
    print("[+] Changing the MAC of "+interface+" to "+new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_regex = r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w'
    current_mac = re.search(mac_regex, ifconfig_result)
    if current_mac:
        return current_mac.group(0)
    else:
        return None


options = get_opts()
if check_opts(options):
    interface = options.interface
    new_mac = options.new_mac

    print("Current MAC = " + str(get_current_mac(interface)))
    change_mac(interface, new_mac)
    if new_mac == get_current_mac(interface):
        print("New MAC = " + str(get_current_mac(interface)))
    else:
        print("[-] Could not change the MAC address")
