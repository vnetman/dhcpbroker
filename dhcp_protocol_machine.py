from enum import Enum, unique
import threading
import queue
import utils
import logging
import random
import time
import select
import struct
from scapy.all import Ether, IP, UDP, BOOTP, DHCP
from dhcp_lease import DhcpLease

# Requests sent from the main thread to the packet engine thread
@unique
class RequestCode(Enum):
    SendPktAwaitResponse = 1
    SendPkt = 2
    Quit = 3

# Responses send back from the packet engine thread to the main thread
@unique
class ResponseCode(Enum):
    Ok = 1
    SendFailed = 2
    RecvError = 3

class DhcpPacketEngine(threading.Thread):

    def __init__(self, interface_name, request_q, response_q):
        super().__init__()

        self.response_q = response_q
        self.request_q = request_q
        self.ifname = interface_name
        
        self.sock_ = utils.make_raw_socket(self.ifname)
    #--------------------

    def __del__(self):
        self.sock_.close()
    #--------------------

    def handle_quit_request(self):
        logging.debug('Packet Engine Thread: handling Quit request')
        
        response = dict()
        response['response'] = ResponseCode.Ok
        self.response_q.put(response)
        time.sleep(0.05)
    #--------------------

    def pkt_is_interesting(self, pkt, mac, xid):
        # In order to discard uninteresting packets quickly, we look
        # at fields in a different order than we logically would.

        if pkt[23] == 0x11: # ip protocol == UDP
            if pkt[34:38] == b'\x00\x43\x00\x44': # check udp src & dest ports
                if xid == struct.unpack('!L', pkt[46:50])[0]: # check xid
                    if pkt[0:6] == mac:
                        logging.debug('Packet Engine Thread: found interesting DHCP packet')
                        return True
        return False
    #--------------------

    def handle_pkt_send_request(self, req_pkt):
        response = dict()

        send_result = self.sock_.send(req_pkt)
        if send_result <= 0:
            logging.debug('Packet Engine Thread: send packet failed')
            response['response'] = ResponseCode.SendFailed
            self.response_q.put(response)
            return
        
        response['response'] = ResponseCode.Ok
        self.response_q.put(response)
        logging.debug('Packet Engine Thread: send packet routine done.')
    #--------------------

    def handle_pkt_send_rcv_request(self, req_pkt, mac, xid, response_collect_await):
        response = dict()

        utils.set_interface_promiscuous_state(self.ifname, 'on')

        send_result = self.sock_.send(req_pkt)
        if send_result <= 0:
            logging.debug('Packet Engine Thread: send packet failed')
            utils.set_interface_promiscuous_state(self.ifname, 'off')
            response['response'] = ResponseCode.SendFailed
            self.response_q.put(response)
            return
        
        collected_replies = []
        then = time.time()
        target = then + response_collect_await

        while True:
            now = time.time()
            if now >= target:
                logging.debug('Packet Engine Thread: time up')
                break

            logging.debug('Packet Engine Thread: waiting for readability')
            (readable, _, errored) = select.select([self.sock_], [], [self.sock_], target - now)
            
            if errored:
                logging.debug('Packet Engine Thread: recv socket error')
                utils.set_interface_promiscuous_state(self.ifname, 'off')
                response['response'] = ResponseCode.RecvError
                self.response_q.put(response)
                return
            
            elif readable:
                pkt = self.sock_.recv(1024)
                if self.pkt_is_interesting(pkt, mac, xid):
                    collected_replies.append(pkt)

        utils.set_interface_promiscuous_state(self.ifname, 'off')
        response = dict()
        response['response'] = ResponseCode.Ok
        response['replies'] = collected_replies
        self.response_q.put(response)
        logging.debug('Packet Engine Thread: submitted interesting packets to main thread')
    #--------------------

    def run(self):
        while True:
            logging.debug('Packet Engine Thread: waiting for requests')
            request = self.request_q.get()
            logging.debug('Packet Engine Thread: got request')

            if request['opcode'] == RequestCode.Quit:
                logging.debug('Packet Engine Thread: asked to stop')
                self.handle_quit_request()
                return
                
            elif request['opcode'] == RequestCode.SendPktAwaitResponse:
                logging.debug('Packet Engine Thread: new send/await request')
                req_pkt = request['packet']
                await_time = request['await_time']
                self.handle_pkt_send_rcv_request(req_pkt, request['mac'], request['xid'], await_time)

            elif request['opcode'] == RequestCode.SendPkt:
                logging.debug('Packet Engine Thread: new send request')
                req_pkt = request['packet']
                self.handle_pkt_send_request(req_pkt)
                
            else:
                assert False, 'Unknown opcode'
    #--------------------

    def stop(self):
        # This is the counterpart of the Thread.start() method, and runs in
        # the context of the *main* (i.e. calling) thread.
        logging.debug('Packet Engine Thread: asking to stop...')
        new_request = dict()
        new_request['opcode'] = RequestCode.Quit
        self.request_q.put(new_request)
        response = self.response_q.get()
        assert response['response'] == ResponseCode.Ok
        self.join()
        logging.debug('Packet Engine Thread: ...stopped')
    #--------------------
                
#--------------------

class DhcpProtocolMachine(object):
    '''Format, send, receive and parse DHCP packets by invoking the DhcpPacketEngine'''
    
    def __init__(self, ifname):
        self.response_q = queue.Queue(maxsize = 1)
        self.request_q = queue.Queue(maxsize = 1)

        self.packet_engine_ = DhcpPacketEngine(ifname, self.request_q,
                                               self.response_q)

    def release_lease(self, lease):
        self.packet_engine_.start()
        request = dict()
        request['opcode'] = RequestCode.SendPkt
        request['packet'] = self.make_dhcp_release_pkt(lease, xid=random.randint(1, 0xffffffff))
        self.request_q.put(request)
        response = self.response_q.get()
        assert response['response'] == ResponseCode.Ok
        self.packet_engine_.stop()

    def obtain_new_lease(self, mac, hostname, preferred_server=None):
        self.packet_engine_.start()

        xid = random.randint(1, 0xffffffff)
        
        request = dict()
        request['opcode'] = RequestCode.SendPktAwaitResponse
        request['xid'] = xid
        request['mac'] = utils.mac_address_human_to_bytes(mac)
        request['packet'] = self.make_dhcp_discover_pkt(mac, hostname, xid)
        request['await_time'] = 4 # seconds
        self.request_q.put(request)

        response = self.response_q.get()
        assert response['response'] == ResponseCode.Ok

        chosen_server = None
        chosen_our_ip = None
        ignored_offers = []
        
        for offer in response['replies']:
            parse_result = self.parse_dhcp_offer_or_ack(offer, xid)
            if 'message-type' not in parse_result:
                continue
            if parse_result['message-type'] != 2: # 2 == offer
                continue
            
            if chosen_server:
                ignored_offers.append(parse_result['siaddr'])
            else:
                if (not preferred_server) or \
                  (preferred_server == parse_result['siaddr']):
                    chosen_server = parse_result['siaddr']
                    chosen_our_ip = parse_result['yiaddr']
                else:
                    ignored_offers.append(parse_result['siaddr'])
                
        if not chosen_server:
            self.packet_engine_.stop()
            return (False, 'no usable offers received', None)

        request = dict()
        request['opcode'] = RequestCode.SendPktAwaitResponse
        request['xid'] = xid
        request['mac'] = utils.mac_address_human_to_bytes(mac)
        request['packet'] = self.make_dhcp_initial_request_pkt(mac, hostname, xid, chosen_server, chosen_our_ip)
        request['await_time'] = 4 # seconds
        self.request_q.put(request)

        response = self.response_q.get()
        assert response['response'] == ResponseCode.Ok
        if not response['replies']:
            self.packet_engine_.stop()
            return (False, 'no leases obtained', None)
            
        if len(response['replies']) > 1:
            self.packet_engine_.stop()
            return (False, 'too many leases (impossible)?', None)

        parse_result = self.parse_dhcp_offer_or_ack(response['replies'][0], xid)
        if ('message-type' not in parse_result) or \
          (parse_result['message-type'] != 5): # 5 = ack
            self.packet_engine_.stop()
            return (False, 'no acknowledgement', None)
        
        self.packet_engine_.stop()

        now = time.time()
        new_lease = DhcpLease(mac, parse_result['yiaddr'], hostname,
                              parse_result['ether_src_address'], chosen_server,
                              now,
                              now + parse_result['renewal_time'],
                              now + parse_result['rebinding_time'],
                              now + parse_result['lease_time'],
                              ignored_offers)
        return (True, 'success', new_lease)
    #--------------------

    def renew_lease(self, lease):
        self.packet_engine_.start()

        xid = random.randint(1, 0xffffffff)
        
        request = dict()
        request['opcode'] = RequestCode.SendPktAwaitResponse
        request['xid'] = xid
        request['mac'] = utils.mac_address_human_to_bytes(lease.mac())
        request['packet'] = self.make_dhcp_renew_pkt(lease, xid)
        request['await_time'] = 4 # seconds
        self.request_q.put(request)

        response = self.response_q.get()
        assert response['response'] == ResponseCode.Ok

        if not response['replies']:
            self.packet_engine_.stop()
            return (None, 'no leases obtained')
            
        if len(response['replies']) > 1:
            self.packet_engine_.stop()
            return (None, 'too many leases (impossible)?')

        parse_result = self.parse_dhcp_offer_or_ack(response['replies'][0], xid)
        if ('message-type' not in parse_result) or \
          (parse_result['message-type'] != 5): # 5 = ack
            self.packet_engine_.stop()
            return (None, 'no acknowledgement')
        
        self.packet_engine_.stop()

        now = time.time()
        new_lease = DhcpLease(lease.mac(), parse_result['yiaddr'], lease.hostname(),
                              parse_result['ether_src_address'],
                              parse_result['siaddr'],
                              now,
                              now + parse_result['renewal_time'],
                              now + parse_result['rebinding_time'],
                              now + parse_result['lease_time'], [])
        return (new_lease, '')
    #--------------------
        
    def make_dhcp_discover_pkt(self, our_mac, our_hostname, xid):
        ###[ Ethernet ]### (dst = ff:ff:ff:ff:ff:ff)(src = 20:47:47:79:62:bf)
        ###[ IP ]###       (src   = 0.0.0.0 dst       = 255.255.255.255)
        ###[ BOOTP ]###    (op    = BOOTREQUEST  xid = 726017164 ciaddr = 0.0.0.0 yiaddr = 0.0.0.0 siaddr = 0.0.0.0 giaddr = 0.0.0.0)
        ###[ DHCP options ]###  options   = [message-type=discover client_id=b'\x01 GGyb\xbf' hostname=b'DESKTOP-7CINUAH' vendor_class_id=b'MSFT 5.0' param_req_list=[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252] end pad pad pad pad]
        
        e = Ether(dst='ff:ff:ff:ff:ff:ff', src=our_mac, type=0x0800)
        i = IP(src='0.0.0.0', dst='255.255.255.255')
        u = UDP(dport=67, sport=68)
        b = BOOTP(op=1, xid=xid, chaddr=utils.mac_address_human_to_bytes(our_mac))
        d = DHCP(options=[('message-type', 'discover'),
                          ('hostname', our_hostname),
                          ('lease_time', 0xffffffff),
                          ('param_req_list', 1, 28, 3, 15, 6),
                          'end'])
        p = e/i/u/b/d
        
        return bytes(p)
    #--------------------

    def make_dhcp_initial_request_pkt(self, our_mac, our_hostname, xid, server_ip_address, requested_ip_address):
        # Initial
        ###[ Ethernet ]### (dst = ff:ff:ff:ff:ff:ff)(src = 20:47:47:79:62:bf)
        ###[ IP ]### (src = 0.0.0.0)(dst = 255.255.255.255)
        ###[ BOOTP ]### (op = BOOTREQUEST)(xid = 726017164)(ciaddr = 0.0.0.0)(yiaddr = 0.0.0.0)(siaddr = 0.0.0.0)(giaddr = 0.0.0.0)(chaddr = ...)
        ###[ DHCP options ]###  options = [message-type=request client_id=b'\x01 GGyb\xbf' requested_addr=192.168.1.166 server_id=192.168.1.9 hostname=b'DESKTOP-7CINUAH' client_FQDN=b'\x00\x00\x00DESKTOP-7CINUAH' vendor_class_id=b'MSFT 5.0' param_req_list=[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252] end]
        
        e = Ether(dst='ff:ff:ff:ff:ff:ff', src=our_mac, type=0x0800)
        i = IP(src='0.0.0.0', dst='255.255.255.255')
        u = UDP(dport=67, sport=68)
        b = BOOTP(op=1, xid=xid, chaddr=utils.mac_address_human_to_bytes(our_mac))
        d = DHCP(options=[('message-type', 'request'),
                          ('client_id', b'\x01' + utils.mac_address_human_to_bytes(our_mac)),
                          ('server_id', server_ip_address),
                          ('requested_addr', requested_ip_address),
                          ('hostname', our_hostname),
                          ('param_req_list', 1, 28, 3, 15, 6),
                          'end'])
        p = e/i/u/b/d
        
        return bytes(p)
    #--------------------

    def make_dhcp_renew_pkt(self, lease, xid):
        # Renewal
        e = Ether(dst='ff:ff:ff:ff:ff:ff', src=lease.mac(), type=0x0800)
        # e = Ether(dst=lease.server_mac(), src=lease.mac(), type=0x0800)
        ###[ Ethernet ]### (dst = 00:1c:c0:34:26:9f)(src = 20:47:47:79:62:bf)

        i = IP(src='0.0.0.0', dst='255.255.255.255')
        #i = IP(src=lease.ip(), dst=lease.server_ip())
        ###[ IP ]### (src = 192.168.1.166)(dst = 192.168.1.9)

        u = UDP(dport=67, sport=68)

        b = BOOTP(op=1, xid=xid, chaddr=utils.mac_address_human_to_bytes(lease.mac()))
        #b = BOOTP(op=1, xid=xid, chaddr=utils.mac_address_human_to_bytes(lease.mac()), ciaddr=lease.ip())
        ###[ BOOTP ]### (op = BOOTREQUEST, xid = 2645962703)(ciaddr = 192.168.1.166)(yiaddr = 0.0.0.0)(siaddr = 0.0.0.0)(giaddr = 0.0.0.0)(chaddr ...)

        d = DHCP(options=[('message-type', 'request'),
                          ('client_id', b'\x01' + utils.mac_address_human_to_bytes(lease.mac())),
                          ('server_id', lease.server_ip()),
                          ('requested_addr', lease.ip()),
                          ('hostname', lease.hostname()),
                          ('param_req_list', 1, 28, 3, 15, 6),
                          'end'])
        ###[ DHCP options ]### options = [message-type=request client_id=b'\x01 GGyb\xbf' hostname=b'DESKTOP-7CINUAH' client_FQDN=b'\x00\x00\x00DESKTOP-7CINUAH' vendor_class_id=b'MSFT 5.0' param_req_list=[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252] end]
        
        p = e/i/u/b/d
        
        return bytes(p)
    #--------------------
    
    def make_dhcp_release_pkt(self, lease, xid):
        e = Ether(dst=lease.server_mac(), src=lease.mac(), type=0x0800)
        ###[ Ethernet ]### (dst = 00:1c:c0:34:26:9f)(src = 20:47:47:79:62:bf)

        i = IP(src=lease.ip(), dst=lease.server_ip())
        ###[ IP ]### (src = 192.168.1.166)(dst = 192.168.1.9)

        u = UDP(dport=67, sport=68)

        b = BOOTP(op=1, xid=xid, chaddr=utils.mac_address_human_to_bytes(lease.mac()), ciaddr=lease.ip())
        ###[ BOOTP ]### (op = BOOTREQUEST, xid = 2951426453)(ciaddr = 192.168.1.166)(yiaddr = 0.0.0.0)(siaddr = 0.0.0.0)(giaddr = 0.0.0.0)(chaddr ...)

        d = DHCP(options=[('message-type', 'release'),
                          ('server_id', lease.server_ip()),
                          ('client_id', b'\x01' + utils.mac_address_human_to_bytes(lease.mac())),                          
                          'end'])
        p = e/i/u/b/d

        return bytes(p)
        
        ###[ DHCP options ]### options = [message-type=release server_id=192.168.1.9 client_id=b'\x01 GGyb\xbf' end pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad]
    #--------------------

    def parse_dhcp_offer_or_ack(self, pkt, xid):
        parse_result = dict()
        
        e = Ether(pkt)

        parse_result['ether_src_address'] = e.src

        # Some conditions ought to be true by the time we get here; assert that they are.
        assert e.type == 0x0800
        i = e.getlayer('IP')

        parse_result['ip_src_address'] = i.src
        parse_result['ip_dst_address'] = i.dst

        assert i.proto == 17
        u = i.getlayer('UDP')
        
        assert u.sport == 67
        assert u.dport == 68
        b = u.getlayer('BOOTP')
        
        assert b.op == 2
        assert b.xid == xid

        parse_result['siaddr'] = b.siaddr
        parse_result['yiaddr'] = b.yiaddr
        
        d = b.getlayer('DHCP')

        for option in d.options:
            if isinstance(option, str):
                assert option == 'end'
                break
            assert isinstance(option, tuple)
            assert isinstance(option[0], str)
            parse_result[option[0]] = option[1]
            print('"{}" => "{}"'.format(option[0], option[1]))

        return parse_result
    #--------------------
