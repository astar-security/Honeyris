#!/usr/bin/python3

########################################################################
# This file is part of the Honeyris project made by the Astar Company: #
# https://github.com/astar-security/Honeyris                           #
# The project is published under GPLv3 license                         #
# Author: David Soria (@Sibwara)                                       #
########################################################################

import subprocess
import pyshark
import argparse
import signal
import socket
from datetime import datetime
from scapy.all import *

ips, gws, macs, nss, dhcp = set(), set(), set(), set(), set()
whitelist, blacklist = None, None
log = [None, None, None]

##################
# Whitelist part #
##################

# Get the local IPv4 addresses which will be whitelisted
def getHoneyIPAddresses(iface, ips):
    try:
        ips.add("127.0.0.1")
        ips.add(get_if_addr(iface))
        print(f"[*] IP addresses of {iface} are : {ips}")
        return 0
    except Exception as e:
        print(f"[!] ERROR : {e}")
        return 1

# Get the local GW which will be whitelisted
def getHoneyGateway(iface, gws, macs):
    try:
        # get default gw for chosen iface
        res = conf.route.route()
        if res[0] == iface :
            gws.add(res[2])
        print(f"[*] Default gateway of {iface} is : {gws}")
        # get associated known MAC address
        res = subprocess.run(["ip", "neigh", "show"], capture_output=True)
        for gw in gws :
            mac = str(res.stdout).split(gw)[1].split("lladdr ")[1].split(" ")[0]
            macs.add(mac)
        print(f"[*] known MAC address of the default gateway is : {macs}")
        return 0
    except Exception as e:
        print(f"[!] ERROR : {e}")
        return 1

# As the DNS will be involved for the system update, it must be whitelisted
def getHoneyDNS(nss):
    try:
        # Parsing the output of the "cat /etc/resolv.conf" command
        res = subprocess.run(["cat", "/etc/resolv.conf"], capture_output=True)
        for ns in str(res.stdout).split("nameserver ")[1:]:
            nss.add(ns.split("\\n")[0])
        print(f"[*] DNS servers of the host are : {nss}")
        return 0
    except Exception as e:
        print(f"[!] ERROR : {e}")
        return 1


# As the DHCP server will be joined to update leases, it must be whitelisted
def getHoneyDHCP(iface, dhcp):
    try:
        conf.checkIPaddr=False
        localmac = get_if_hwaddr(iface)
        localmacraw = get_if_raw_hwaddr(iface)[1]
        dhcp_discover = (Ether(src=localmac, dst='ff:ff:ff:ff:ff:ff') / 
            IP(src='0.0.0.0', dst='255.255.255.255') / 
            UDP(dport=67, sport=68) / 
            BOOTP(chaddr=localmacraw,xid=5555) / 
            DHCP(options=[('message-type', 'discover'), 'end']))
        dhcp_offer = srp1(dhcp_discover,iface=iface, verbose=0, timeout=10)
        dhcp.add(dhcp_offer['IP'].src)
        print(f"[*] DHCP server is {dhcp}")
        return 0
    except Exception as e:
        print(f"[!] ERROR : {e}")
        return 1

"""
# As the honeyris server will join targets to update, they must be whitelisted
def getHoneyUpdater():
    global repositories
    f = open(repositories, "r")
    rep = f.read().split('\n')
    f.close()
"""
####################
# Prepare the meal #
####################

def populate(iface):
    global ips
    global gws
    global macs
    global nss
    global dhcp
    global whitelist
    global blacklist
#    global repositories

    getHoneyIPAddresses(iface, ips)
    getHoneyGateway(iface, gws, macs)
    getHoneyDNS(nss)
    getHoneyDHCP(iface, dhcp)
    whitelist = ips.union(gws.union(nss.union(dhcp)))
    blacklist = set()

def setLog(siem):
    global log
    global ips
    global gws
    global macs
    global nss
    global dhcp
    
    
    log[1] = siem
    log[2] =  514
    
    try:
        # check if a specific port is provided
        dest = siem.split(":")
        if len(dest) == 2:
            log[1] = dest[0]
            log[2] = int(dest[1])
        # set UDP socket
        log[0] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # provide information about honeyris
        info = f"INFO-Trusted information-Honeyris IP address:{ips}-Honeyris GW address/MAC:{gws}{macs}-Honeyris NS address:{nss}-Honeyris DHCP:{dhcp}"
        log[0].sendto(bytes(info,"utf-8"), (log[1],log[2]))
        print(f"[*] Logging initiated")
        return 0
    except Exception as e:
        print(f"[!] ERROR : {e}")
        return 1

def logMeThat(ip, date, attack, packet, verbose):
    global log
    print(f"[+] {date}: {ip} wants some honey from us through {attack}")
    warn = f"WARNING-{date}-{ip}-{attack}"
    if verbose:
        warn += f"-{str(packet)}"
    log[0].sendto(bytes(warn,"utf-8"),(log[1],log[2])) 

def ctrlCHandler(signum, frame):
    global log
    global blacklist
    print(f"[!] quitting...")
    log[0].close()
    print(f"Blacklist: {blacklist}")

signal.signal(signal.SIGINT, ctrlCHandler)

####################
# Serve some honey #
####################

def blacklistIP(iface, IP, ARPPing, ARPSpoof, verbose):
    global gws
    global ips
    global macs
    global nss
    global dhcp
    global whitelist
    global blacklist

    try:
        capture = pyshark.LiveCapture(interface=iface)
        for packet in capture.sniff_continuously():
        
            # if an IP request does not come from a trusted IP
            if (IP and 'IP' in packet and packet['ip'].dst in ips and 
                    packet['ip'].src not in whitelist):
                blacklist.add(packet['ip'].src)
                logMeThat(packet['ip'].src, datetime.today().isoformat(), 
                        "IP request", packet, verbose)
            
            # if a ARP request does not come from a trusted IP   
            elif (ARPPing and 'ARP' in packet and packet['arp'].opcode == '1'  
            and packet['arp'].dst_proto_ipv4 in ips 
            and packet['arp'].src_proto_ipv4 not in whitelist):
                blacklist.add(packet['arp'].src_proto_ipv4)
                logMeThat(packet['arp'].src_proto_ipv4, datetime.today().isoformat(), 
                        "ARP ping", packet, verbose)

            # if a ARP reply of the gateway does not come from a trusted MAC   
            elif (ARPSpoof and 'ARP' in packet and packet['arp'].opcode == '2'  
            and packet['arp'].src_hw_mac not in macs 
            and packet['arp'].src_proto_ipv4 in gws):
                blacklist.add(packet['arp'].src_proto_ipv4)
                logMeThat(packet['arp'].src_hw_mac, datetime.today().isoformat(), 
                        "ARP spoof", packet, verbose)
    except Exception as e:
        print(f"[!] {e} occurs")


def main():
    parser = argparse.ArgumentParser(description='Detect suspucious activity from '\
            'the network', add_help=True)
    parser.add_argument('--ip', action="store_true", dest="IP", default=False,
            help='Enable IP touch blacklist')
    parser.add_argument('--arpping', action="store_true", dest="ARPPing", default=False,
            help='Enable ARP ping blacklist')
    parser.add_argument('--arpspoof', action="store_true", dest="ARPSpoof", default=False,
            help='Enable ARP spoof blacklist')   
    parser.add_argument('--verbose', action="store_true", dest="verbose", default=False,
            help="Include packet received from suspicious IP, WARNING : can contain sensitive data")
    parser.add_argument('iface', 
            help="the network interface to monitor")
    parser.add_argument('siem', 
            help="the server to send the UDP syslog alerts, can be 127.0.0.1:514")
    args = parser.parse_args()
    populate(args.iface)
    setLog(args.siem)
    blacklistIP(args.iface, args.IP, args.ARPPing, args.ARPSpoof, args.verbose)

if __name__ == '__main__':
    main()

