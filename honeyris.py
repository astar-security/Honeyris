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
from datetime import datetime

ips, gws, macs, nss, whitelist, blacklist = None, None, None, None, None, None
log, logfile = None, None

# Get the local IPv4 addresses which will be whitelisted
def getHoneyIPAddresses():
    try:
        # Parsing the output of the "ip a" command
        res = subprocess.run(["ip", "a"], capture_output=True)
        ips = set()
        for ip in str(res.stdout).split("inet ")[1:]:
            ips.add(ip.split("/")[0])
        return ips
    except Exception as e:
        print(f"[!] ERROR : {e}")
        return 1

# Get the local GW which will be whitelisted
def getHoneyGateway():
    try:
        # Parsing the output of the "ip r" command
        res = subprocess.run(["ip", "r"], capture_output=True)
        gws = set()
        for gw in str(res.stdout).split("default via ")[1:]:
            gws.add(gw.split(" ")[0])
        macs = set()
        res = subprocess.run(["ip", "neigh", "show"], capture_output=True)
        for gw in gws :
            mac = str(res.stdout).split(gw)[1].split("lladdr ")[1].split(" ")[0]
            macs.add(mac)
        return gws, macs
    except Exception as e:
        print(f"[!] ERROR : {e}")
        return 1,1

# As the DNS will be involved for the system update, it must be whitelisted
def getHoneyDNS():
    try:
        # Parsing the output of the "cat /etc/resolv.conf" command
        res = subprocess.run(["cat", "/etc/resolv.conf"], capture_output=True)
        nss = set()
        for ns in str(res.stdout).split("nameserver ")[1:]:
            nss.add(ns.split("\\n")[0])
        return nss
    except Exception as e:
        print(f"[!] ERROR : {e}")
        return 1

# As the DHCP server will be joined to update leases, it must be whitelisted
#def getHoneyDHCP():

# As the honeyris server will join targets to update, they must be whitelisted
#def getHoneyUpdater():

def populate():
    global ips
    global gws
    global macs
    global nss
    global whitelist
    global blacklist

    ips = getHoneyIPAddresses()
    gws,macs = getHoneyGateway()
    nss = getHoneyDNS()
    whitelist = ips.union(gws.union(nss))
    blacklist = set()

def setLog():
    global logfile
    global log
    logfilename = f"{datetime.today().isoformat()}_honey.logs"
    logfile = open(logfilename, "w")
    logfile.write(f"Trusted information:\nHoneyris IP address: {ips}\nHoneyris gw address and macs: {gws} {macs}\nHoneyris NS address: {nss}\n\nHits:\n")
    log = {}

def logMeThat(ip, date, attack, packet):
    global log
    global logfile
    if ip not in log:
        log[ip] = {}
    log[ip][date] = {attack:str(packet)}
    print(f"[+] {date}: {ip} wants some honey from us through {attack}")
    logfile.write(f"Hit : {date} : {ip} : {attack} : {str(packet)}") 

def ctrlCHandler(signum, frame):
    global logfile
    global blacklist
    print(f"[!] quitting...")
    logfile.close()
    print(f"Blacklist: {blacklist}")

signal.signal(signal.SIGINT, ctrlCHandler)

def blacklistIP(IP, ARPPing, ARPSpoof):
    global gws
    global ips
    global macs
    global nss
    global whitelist
    global blacklist

    try:
        capture = pyshark.LiveCapture(interface='any')
        for packet in capture.sniff_continuously():
        
            # if a IP request does not come from a trusted IP
            if (IP and 'IP' in packet and packet['ip'].dst in ips and 
                    packet['ip'].src not in whitelist):
                blacklist.add(packet['ip'].src)
                logMeThat(packet['ip'].src, datetime.today().isoformat(), 
                        "IP request", packet)
            
            # if a ARP request does not come from a trusted IP   
            elif (ARPPing and 'ARP' in packet and packet['arp'].opcode == '1'  
            and packet['arp'].dst_proto_ipv4 in ips 
            and packet['arp'].src_proto_ipv4 not in whitelist):
                blacklist.add(packet['arp'].src_proto_ipv4)
                logMeThat(packet['arp'].src_proto_ipv4, datetime.today().isoformat(), 
                        "ARP ping", packet)

            # if a ARP reply of the gateway does not come from a trusted MAC   
            elif (ARPSpoof and 'ARP' in packet and packet['arp'].opcode == '2'  
            and packet['arp'].src_hw_mac not in macs 
            and packet['arp'].src_proto_ipv4 in gws):
                blacklist.add(packet['arp'].src_proto_ipv4)
                logMeThat(packet['arp'].src_hw_mac, datetime.today().isoformat(), 
                        "ARP spoof", packet)
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
    args = parser.parse_args()
    populate()
    setLog()
    blacklistIP(args.IP, args.ARPPing, args.ARPSpoof)


if __name__ == '__main__':
    main()

