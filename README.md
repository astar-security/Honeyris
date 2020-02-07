# Honeyris
A cost effective way to detect intrusion in your network in the form of a "Honeypot as a SIEM" (HaaS)

## Purpose
Because every company connot buy a AAA SIEM with scalability, log parsing, false positive management, AI, etc. Honeyris offers an alternative way to spot an "in progress intrusion" in your network.  

The main principe is to provide a honeypot which has no reason to be reached by a trusted asset. So, if this honeypot receives packets (except broadcast ones), you can assume that either there is a misconfigured asset in your network (and you should investigate its behaviour to avoid useless traffic) or there is an attacker who try to perform lateral movement (so at least one asset is probably already compromised but you still have the time to stop its spread)

## Mechanics
The **Honeyris** honeypot is configured to simulate a reachable service on the 65 536 TCP and UDP ports and to answer to every ICMP/ARP request.  
This way, you can spot :
- nmap scanning
- nbtscan scanning
- arpscan scanning
- responder poisoning 
- ARP poisoning 
- distributed eternalblue
- ...

## Usage
The basic command line is :  
```
python3 honeyris.py --ip --arpping --arpspoof eth0 127.0.0.1:514
```
You should disable --arpspoof if your gateway is a virtual IP which can commonly change its MAC address.  

The `--verbose` option will log the packet content which trigger the alert.

## Blindspot & limitation
This approach can work only if you do not have too much assets which perform some kind of scanning of your network (or you can whitelist their IP addresses).  

Also, you need to have your own way to manage the alert raised by Honeyris to be able to stop the attacker as soon as possible. By default, Honeyris provide UDP SYSLOG alert.  

The most effective way to cover your network is to put a honeyris instance in every subnet. Maybe it will be easier to deploy if switches integrate this kind of apporach.  

If the attacker stay on the machine he powned and does not try lateral movement, you will not be able to catch it.  
So, to be effective, this tool should be combined with the baselines of the information security monitoring:
* Multiple failed login attempts against corporate account(s)
* Every hit on a "DENY" rule of the firewall from the internal network
* Every alert of the Antivirus endpoint agent
