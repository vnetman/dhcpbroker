import socket
import threading
import select
from queue import Queue
from scapy.all import *
from utils import mac_address_human_to_bytes, set_interface_promiscuous_state, make_raw_socket
import random
from enum import Enum, unique
import logging

# Requests sent from the main thread to the packet engine thread
@unique
class RequestCode(Enum):
    SendPktAwaitResponse = 1
    Quit = 2

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
        
        self.sock_ = make_raw_socket(self.ifname)
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

    def handle_pkt_send_rcv_request(self, req_pkt, mac, xid, response_collect_await):
        response = dict()

        set_interface_promiscuous_state(self.ifname, 'on')

        send_result = self.sock_.send(req_pkt)
        if send_result <= 0:
            logging.debug('Packet Engine Thread: send packet failed')
            set_interface_promiscuous_state(self.ifname, 'off')
            response['response'] = ResponseCode.SendFailed
            self.response_q.put(response)
            return
        
        collected_replies = []
        then = time.time()
        while True:
            now = time.time()
            if (now - then) >= response_collect_await:
                logging.debug('Packet Engine Thread: time up')
                break

            try:
                logging.debug('Packet Engine Thread: waiting for readability')
                (readable, _, errored) = select([self.sock_], [], [self.sock_], 60)
            except TimeoutException:
                logging.debug('Packet Engine Thread: time up, no packets')
                break
            
            if errored:
                logging.debug('Packet Engine Thread: recv socket error')
                set_interface_promiscuous_state(self.ifname, 'off')
                response['response'] = ResponseCode.RecvError
                self.response_q.put(response)
                return
            
            pkt = self.sock_.recv(1024)
            
            if self.pkt_is_interesting(pkt, mac, xid):
                collected_replies.append(pkt)

        set_interface_promiscuous_state(self.ifname, 'off')
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
        self.response_q = Queue(maxsize = 1)
        self.request_q = Queue(maxsize = 1)

        self.packet_engine_ = DhcpPacketEngine(ifname, self.request_q,
                                               self.response_q)

    def obtain_new_lease(self, mac, hostname, preferred_server=None):
        self.packet_engine_.start()

        xid = random.randint(1, 0xffffffff)
        
        request = dict()
        request['opcode'] = RequestCode.SendPktAwaitResponse
        request['xid'] = xid
        request['mac'] = mac_address_human_to_bytes(mac)
        request['packet'] = self.make_dhcp_discover_pkt(mac, hostname, xid)
        request['await_time'] = 4 # seconds
        self.request_q.put(request)

        response = self.response_q.get()
        assert response['response'] == ResponseCode.Ok

        chosen_server = None
        chosen_our_ip = None
        
        offers = response['replies']
        for offer in offers:
            parse_result = self.parse_dhcp_offer_or_ack(offer, xid)
            if not chosen_server:
                if (not preferred_server) or \
                  (preferred_server == parse_result['siaddr']):
                    chosen_server = parse_result['siaddr']
                    chosen_our_ip = parse_result['yiaddr']
                    break
                
        if not chosen_server:
            print('Error; no offers')
            self.packet_engine_.stop()
            return (False, 'no offers received', None)

        request = dict()
        request['opcode'] = RequestCode.SendPktAwaitResponse
        request['xid'] = xid
        request['mac'] = mac
        request['packet'] = self.make_dhcp_request_pkt(mac, hostname, xid, chosen_server, chosen_our_ip)
        request['await_time'] = 4 # seconds
        self.request_q.put(request)

        response = self.response_q.get()
        assert response['response'] == ResponseCode.Ok
        
        self.packet_engine_.stop()
        return (False, 'not implemented', None)
        
    def make_dhcp_discover_pkt(self, our_mac, our_hostname, xid):
        e = Ether(dst='ff:ff:ff:ff:ff:ff', src=our_mac, type=0x0800)
        i = IP(src='0.0.0.0', dst='255.255.255.255')
        u = UDP(dport=67, sport=68)
        b = BOOTP(op=1, xid=xid, chaddr=mac_address_human_to_bytes(our_mac))
        d = DHCP(options=[('message-type', 'discover'),
                          ('hostname', our_hostname),
                          ('param_req_list', 1, 28, 3, 15, 6),
                          'end'])
        p = e/i/u/b/d
        
        return bytes(p)
    #--------------------

    def make_dhcp_request_pkt(self, our_mac, our_hostname, xid, server_ip_address, requested_ip_address):
        e = Ether(dst='ff:ff:ff:ff:ff:ff', src=our_mac, type=0x0800)
        i = IP(src='0.0.0.0', dst='255.255.255.255')
        u = UDP(dport=67, sport=68)
        b = BOOTP(op=1, xid=xid, chaddr=mac_address_human_to_bytes(our_mac))
        d = DHCP(options=[('message-type', 'request'),
                          ('server_id', server_ip_address),
                          ('requested_addr', requested_ip_address),
                          ('hostname', our_hostname),
                          ('param_req_list', 1, 28, 3, 15, 6),
                          'end'])
        p = e/i/u/b/d
        
        return bytes(p)
    #--------------------

    def parse_dhcp_offer_or_ack(self, pkt, xid):
        parse_result = dict()
        
        e = Ether(pkt)

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

        return parse_result
    #--------------------
            
        
                              
