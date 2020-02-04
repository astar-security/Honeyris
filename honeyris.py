#!/usr/bin/python3

########################################################################
# This file is part of the Honeyris project made by the Astar Company: #
# https://github.com/astar-security/Honeyris                           #
# The project is published under GPLv3 license                         #
# Author: David Soria (@Sibwara)                                       #
########################################################################

import pyshark
import argparse
import logging
import logging.handlers
import signal
from scapy.all import *

blacklist = None
log = None

##################
# Whitelist part #
##################

# Get the local IPv4 addresses which will be whitelisted
def getHoneyIPAddresses(iface):
    global log
    ips = set()
    try:
        ips.add("127.0.0.1")
        ips.add(get_if_addr(iface))
        return ips
    except Exception as e:
        log.error(f"Error during local IP collection: {e}")
        return ips

# Get the local GW which will be whitelisted
def getHoneyGateway(iface):
    global log
    gws, macs = set(), set()
    try:
        # get default gw for chosen iface
        res = conf.route.route()
        if res[0] == iface :
            gws.add(res[2])
        # get associated known MAC address
        arp = open("/proc/net/arp","r")
        table = arp.read()
        for gw in gws :
            mac = table.split(gw)[1].split("\n")[0].split()[2]
            macs.add(mac)
        return gws, macs
    except Exception as e:
        log.error(f"Error during gateway collection: {e}")
        return gws, macs

# As the DNS will be involved for the system update, it must be whitelisted
def getHoneyDNS():
    global log
    nss = set()
    try:
        # Parsing the content of "/etc/resolv.conf" 
        resol = open("/etc/resolv.conf", "r")
        dns = resol.read().split("nameserver ")[1:]
        resol.close()
        for ns in dns:
            nss.add(ns.split("\n")[0])
        return nss
    except Exception as e:
        log.error(f"Error during DNS collection: {e}")
        return nss


# As the DHCP server will be joined to update leases, it must be whitelisted
def getHoneyDHCP(iface):
    global log
    dhcp = set()
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
        return dhcp
    except Exception as e:
        log.error(f"Error during DHCP collection: {e}")
        return dhcp

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
    global log
    global blacklist

    ips = getHoneyIPAddresses(iface)
    gws, macs = getHoneyGateway(iface)
    nss = getHoneyDNS()
    dhcp = getHoneyDHCP(iface)
    whitelist = ips.union(gws.union(nss.union(dhcp)))
    blacklist = set()
    
    # provide information about honeyris
    info = "Information about Honeyris-"\
        f"Interface:{iface}-IP:{ips}-Gateway:{gws}{macs}-NS:{nss}-DHCP:{dhcp}"
    log.info(info)
    return ips,gws,macs,nss,dhcp,whitelist


def setLog(siem):
    global log
    
    port =  514
    
    log = logging.getLogger('Honeyris')
    log.setLevel(logging.INFO)
    formatter = logging.Formatter('%(name)s--%(levelname)s--%(asctime)s--%(message)s')
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    log.addHandler(console)

    try:
        # check if a specific port is provided
        dest = siem.split(":")
        if len(dest) == 2:
            siem = dest[0]
            port = int(dest[1])
        # set UDP socket
        syslog = logging.handlers.SysLogHandler(address=(siem, port))
        syslog.setFormatter(formatter)
        log.addHandler(syslog)

        log.info("Logging ready")
        return 0
    except Exception as e:
        log.error(f"Error during logging initialization: {e}")
        return 1

def ctrlCHandler(signum, frame):
    global log
    global blacklist
    log.info(f"quitting...")
    log.info(f"Blacklisted targets were: {blacklist}")

signal.signal(signal.SIGINT, ctrlCHandler)

####################
# Serve some honey #
####################

def blacklistIP(iface, IP, ARPPing, ARPSpoof, verbose, whitelist, ips, gws, macs):
    global blacklist
    global log

    log.info("Logging initiated")
    try:
        capture = pyshark.LiveCapture(interface=iface)
        for packet in capture.sniff_continuously():
        
            # if an IP request does not come from a trusted IP
            if (IP and 'IP' in packet and packet['ip'].dst in ips and 
                    packet['ip'].src not in whitelist):
                blacklist.add(packet['ip'].src)
                log.warning(f"{packet['ip'].src}--IP request" + ['', f"--{packet}"][verbose])
            
            # if a ARP request does not come from a trusted IP   
            elif (ARPPing and 'ARP' in packet and packet['arp'].opcode == '1'  
            and packet['arp'].dst_proto_ipv4 in ips 
            and packet['arp'].src_proto_ipv4 not in whitelist):
                blacklist.add(packet['arp'].src_proto_ipv4)
                log.warning(f"{packet['arp'].src_proto_ipv4}--ARP ping" + ['', f"--{packet}"][verbose])

            # if a ARP reply of the gateway does not come from a trusted MAC   
            elif (ARPSpoof and 'ARP' in packet and packet['arp'].opcode == '2'  
            and packet['arp'].src_hw_mac not in macs 
            and packet['arp'].src_proto_ipv4 in gws):
                blacklist.add(packet['arp'].src_proto_ipv4)
                log.warning(f"{packet['arp'].src_hw_mac}--ARP spoof" + ['', f"--{packet}"][verbose])
    except Exception as e:
        log.error(f"Error during packet capture: {e}")


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
            help="Include packet content received from suspicious IP, WARNING : sensitive data could be transmitted through UDP syslog (cleartext)")
    parser.add_argument('iface', 
            help="the network interface to monitor")
    parser.add_argument('siem', 
            help="the server to send the UDP syslog alerts, can be 127.0.0.1:514")
    args = parser.parse_args()
    
    setLog(args.siem)
    ips, gws, macs, nss, dhcp, whitelist = populate(args.iface)
    blacklistIP(args.iface, args.IP, args.ARPPing, args.ARPSpoof, args.verbose, whitelist, ips, gws, macs)

if __name__ == '__main__':
    main()

