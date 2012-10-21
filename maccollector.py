from socket import *
from eappacket import *

def main():
    # bind the h3c client to the EAP protocal 
    client = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_PAE))
    client.bind(('eth0', ETHERTYPE_PAE))
    # get local ethernet card address
    while 1:
        try:
            packet = client.recv(1600)
            # print packet
        except error , msg:
            print "Connection error!"
            exit(-1)
        strip_eap_resp_id_packet(packet)

def strip_eap_resp_id_packet(eap_packet):
    eapol_ver, eapol_type, eapol_len = unpack("!BBH",eap_packet[14:18])

    if eapol_type == EAPOL_EAPPACKET:
        eap_code, eap_id, eap_len = unpack("!BBH", eap_packet[18:22])
    else:
        return

    if eap_code == EAP_RESPONSE:
        display_mac_username(eap_packet)

def display_mac_username(packet):
    pretty_mac = ':'.join('%02x' % ord(b) for b in packet[6:12])
    account_idx = packet[22:].rindex('\x20')
    print "Mac:", pretty_mac, "Username: %s" %(packet[23+account_idx:])

if __name__ == '__main__':
    main()


    def send_logoff(self):
        # invoke plugins 
        self.invoke_plugins('after_logoff')

        # sent eapol logoff packet
        eap_logoff_packet = self.ethernet_header + get_EAPOL(EAPOL_LOGOFF)
        self.client.send(eap_logoff_packet)
        self.has_sent_logoff = True

        display_prompt(Fore.GREEN, 'Sending EAPOL logoff')

    def send_response_id(self, packet_id):
        self.client.send(self.ethernet_header + 
                get_EAPOL(EAPOL_EAPPACKET,
                    get_EAP(EAP_RESPONSE,
                        packet_id,
                        EAP_TYPE_ID,
                        "\x06\x07bjQ7SE8BZ3MqHhs3clMregcDY3Y=\x20\x20"+ self.login_info[0])))

    def send_response_md5(self, packet_id, md5data):
        md5 = self.login_info[1][0:16]
        if len(md5) < 16:
            md5 = md5 + '\x00' * (16 - len (md5))
        chap = []
        for i in xrange(0, 16):
            chap.append(chr(ord(md5[i]) ^ ord(md5data[i])))
        resp = chr(len(chap)) + ''.join(chap) + self.login_info[0]
        eap_packet = self.ethernet_header + get_EAPOL(EAPOL_EAPPACKET, get_EAP(EAP_RESPONSE, packet_id, EAP_TYPE_MD5, resp))
        try:
            self.client.send(eap_packet)
        except socket.error, msg:
            print "Connection error!"
            exit(-1)

    def send_response_h3c(self, packet_id):
        resp=chr(len(self.login_info[1]))+self.login_info[1]+self.login_info[0]
        eap_packet = self.ethernet_header + get_EAPOL(EAPOL_EAPPACKET, get_EAP(EAP_RESPONSE, packet_id, EAP_TYPE_H3C, resp))
        try:
            self.client.send(eap_packet)
        except socket.error, msg:
            print "Connection error!"
            exit(-1)

    def display_login_message(self, msg):
        """
            display the messages received form the radius server,
            including the error meaasge after logging failed or 
            other meaasge from networking centre
        """
        try:
            print msg.decode('gbk')
        except UnicodeDecodeError:
            print msg


    def EAP_handler(self, eap_packet):
        vers, type, eapol_len  = unpack("!BBH",eap_packet[:4])
        if type == EAPOL_EAPPACKET:
            code, id, eap_len = unpack("!BBH", eap_packet[4:8])
            if code == EAP_SUCCESS:
                display_prompt(Fore.YELLOW, 'Got EAP Success')
                # invoke plugins 
                self.invoke_plugins('after_auth_succ')
                daemonize('/dev/null','/tmp/daemon.log','/tmp/daemon.log')
            elif code == EAP_FAILURE:
                if (self.has_sent_logoff):
                    display_prompt(Fore.YELLOW, 'Logoff Successfully!')
                    # invoke plugins 
                    self.invoke_plugins('after_logoff')
                    self.display_login_message(eap_packet[10:])
                else:
                    display_prompt(Fore.YELLOW, 'Got EAP Failure')
                    # invoke plugins 
                    self.invoke_plugins('after_auth_fail')
                    self.display_login_message(eap_packet[10:])
                exit(-1)
            elif code == EAP_RESPONSE:
                display_prompt(Fore.YELLOW, 'Got Unknown EAP Response')
            elif code == EAP_REQUEST:
                reqtype = unpack("!B", eap_packet[8:9])[0]
                reqdata = eap_packet[9:4 + eap_len]
                if reqtype == EAP_TYPE_ID:
                    display_prompt(Fore.YELLOW, 'Got EAP Request for identity')
                    self.send_response_id(id)
                    display_prompt(Fore.GREEN, 'Sending EAP response with identity = [%s]' % self.login_info[0])
                elif reqtype == EAP_TYPE_H3C:
                    display_prompt(Fore.YELLOW, 'Got EAP Request for Allocation')
                    self.send_response_h3c(id)
                    display_prompt(Fore.GREEN, 'Sending EAP response with password')
                elif reqtype == EAP_TYPE_MD5:
                    data_len = unpack("!B", reqdata[0:1])[0]
                    md5data = reqdata[1:1 + data_len]
                    display_prompt(Fore.YELLOW, 'Got EAP Request for MD5-Challenge')
                    self.send_response_md5(id, md5data)
                    display_prompt(Fore.GREEN, 'Sending EAP response with password')
                else:
                    display_prompt(Fore.YELLOW, 'Got unknown Request type (%i)' % reqtype)
            elif code==10 and id==5:
                self.display_login_message(eap_packet[12:])
            else:
                display_prompt(Fore.YELLOW, 'Got unknown EAP code (%i)' % code)
        else:
            display_prompt(Fore.YELLOW, 'Got unknown EAPOL type %i' % type)

    def serve_forever(self):
        try:
            #print self.login_info
            self.load_plugins()
            self.send_start()
        except KeyboardInterrupt:
            print Fore.RED + Style.BRIGHT + 'Interrupted by user' + Style.RESET_ALL
            self.send_logoff()
