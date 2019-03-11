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

@unique
class RequestCode(Enum):
    '''Requests sent from the main thread to the packet engine thread
    '''
    SendPktAwaitResponse = 1
    SendPkt = 2
    Quit = 3
#===

@unique
class ResponseCode(Enum):
    '''Responses sent back from the packet engine thread to the main thread
    '''
    Ok = 1
    SendFailed = 2
    RecvError = 3
#===

class DhcpPacketEngine(threading.Thread):
    '''Thread subclass that waits for commands from the main program, does
    socket i/o, and sends responses back to the main program'''

    def __init__(self, interface_name, request_q, response_q):
        super().__init__()

        self.response_q = response_q
        self.request_q = request_q
        self.ifname = interface_name

        self.sock_ = utils.make_raw_socket(self.ifname)
    #---

    def __del__(self):
        self.sock_.close()
    #---

    def handle_quit_request(self):
        logging.debug('Packet Engine Thread: handling Quit request')

        response = dict()
        response['response'] = ResponseCode.Ok
        self.response_q.put(response)
        time.sleep(0.05)
    #---

    def pkt_is_interesting(self, pkt, mac, xid):
        # In order to discard uninteresting packets quickly, we look
        # at fields in a different order than we logically would.

        if pkt[23] != 0x11: # ip protocol == UDP
            return False
        
        if pkt[34:38] != b'\x00\x43\x00\x44': # check udp src & dest ports
            return False
        
        if xid != struct.unpack('!L', pkt[46:50])[0]: # check xid
            return False
        
        if (pkt[0:6] != mac) and (pkt[0:6] != b'\xff\xff\xff\xff\xff\xff'):
            return False
        
        logging.debug('Packet Engine Thread: found interesting DHCP packet')
        return True
    #---

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
    #---

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

        logging.debug('Packet Engine Thread: submitted {} interesting packets to main thread'.format(len(collected_replies)))
    #---

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
    #---

    def stop(self):
        ''' This is the counterpart of the Thread.start() method, and runs in
        the context of the *main* (i.e. calling) thread. Essentially we just
        post a Quit request to the thread.'''

        logging.debug('Packet Engine Thread: asking to stop...')
        new_request = dict()
        new_request['opcode'] = RequestCode.Quit
        self.request_q.put(new_request)
        response = self.response_q.get()
        assert response['response'] == ResponseCode.Ok
        self.join()
        logging.debug('Packet Engine Thread: ...stopped')
    #---

#===

class DhcpProtocolMachine(object):
    '''Format, send, receive and parse DHCP packets by invoking the
    DhcpPacketEngine'''

    def __init__(self, ifname):
        self.response_q = queue.Queue(maxsize = 1)
        self.request_q = queue.Queue(maxsize = 1)

        self.packet_engine_ = DhcpPacketEngine(ifname, self.request_q,
                                               self.response_q)
        self.packet_engine_.start()
    #---

    def __del__(self):
        logging.debug('Protocol machine: asking packet thread to stop')
        self.packet_engine_.stop()
    #---

    def release_lease(self, lease):
        request = dict()
        request['opcode'] = RequestCode.SendPkt
        request['packet'] = self.make_dhcp_release_pkt(lease, xid=random.randint(1, 0xffffffff))

        logging.info('Protocol machine: Placing request to send DHCPRELEASE...')
        self.request_q.put(request)
        
        logging.debug('Protocol machine: ... request placed, waiting for send...')
        response = self.response_q.get()
        logging.debug('Protocol machine: ... sent')
        assert response['response'] == ResponseCode.Ok
    #---

    def obtain_new_lease(self, mac, hostname, preferred_server=None):
        '''Manufacture and send a DHCPDISCOVER, wait for and process the
        DHCPOFFER. Then invoke request_lease() to send the DHCPREQUEST.
        '''
        xid = random.randint(1, 0xffffffff)

        request = dict()
        request['opcode'] = RequestCode.SendPktAwaitResponse
        request['xid'] = xid
        request['mac'] = utils.mac_address_human_to_bytes(mac)
        request['packet'] = self.make_dhcp_discover_pkt(mac, hostname, xid)
        request['await_time'] = 4 # seconds

        logging.info('Protocol machine: Placing request to send DHCPDISCOVER...')
        self.request_q.put(request)

        logging.debug('Protocol machine: ... request placed, waiting for responses...')
        response = self.response_q.get()
        
        logging.debug('Protocol machine: response code {}, {} '
                      'replies'.format(response['response'],
                                       len(response['replies'])))
        
        assert response['response'] == ResponseCode.Ok

        chosen_server = None
        chosen_our_ip = None
        ignored_offers = []

        for offer in response['replies']:
            parse_result = self.parse_dhcp_offer_or_ack(offer, xid)
            if 'message-type' not in parse_result:
                logging.debug('Protocol machine: rejecting: no message-type option')
                continue
            if parse_result['message-type'] != 2: # 2 == offer
                logging.debug('Protocol machine: rejecting: not a DHCPOFFER')
                continue

            if chosen_server:
                ignored_offers.append(parse_result['siaddr'])
                logging.debug('Protocol machine: ignoring offer from {}'.format(parse_result['siaddr']))
            else:
                if (not preferred_server) or \
                  (preferred_server == parse_result['siaddr']):
                    chosen_server = parse_result['siaddr']
                    chosen_our_ip = parse_result['yiaddr']
                    logging.info('Protocol machine: good offer {} from {}'.format(chosen_our_ip, chosen_server))
                else:
                    ignored_offers.append(parse_result['siaddr'])
                    logging.debug('Protocol machine: ignoring offer from {}'.format(parse_result['siaddr']))

        if not chosen_server:
            return (None, 'no usable offers received')

        lease, errstr = self.request_lease(xid, mac, hostname, chosen_server, chosen_our_ip, True)

        for i in ignored_offers:
            lease.add_to_ignored_offers(i)
        
        return (lease, errstr)
    #---

    def request_lease(self, xid, mac, hostname, server_ip, our_ip, selecting):
        '''Manufacture and send a DHCPREQUEST message, wait for and process the
        DHCPACK.
        This method is invoked for both the fresh lease as well as the rebind
        cases.'''

        request = dict()
        request['opcode'] = RequestCode.SendPktAwaitResponse
        request['xid'] = xid
        request['mac'] = utils.mac_address_human_to_bytes(mac)
        request['packet'] = self.make_dhcp_request_pkt(mac, hostname, xid, server_ip, our_ip, selecting)
        request['await_time'] = 4 # seconds

        logging.info('Protocol machine: Placing request to send DHCPREQUEST...')
        self.request_q.put(request)

        logging.debug('Protocol machine: ... request placed, waiting for responses...')
        response = self.response_q.get()

        logging.debug('Protocol machine: response code {}, {} '
                      'replies'.format(response['response'],
                                       len(response['replies'])))
        
        assert response['response'] == ResponseCode.Ok
        if not response['replies']:
            return None, 'no leases obtained'

        if len(response['replies']) > 1:
            return None, 'too many leases (impossible)?'

        parse_result = self.parse_dhcp_offer_or_ack(response['replies'][0], xid)
        if ('message-type' not in parse_result) or \
          (parse_result['message-type'] != 5): # 5 = ack
            return None, 'no acknowledgement'

        logging.info('Protocol machine: DHCPACK received, preparing lease')
        
        now = time.time()
        renew_ts = None if 'renewal_time' not in parse_result else parse_result['renewal_time'] + now
        rebind_ts = None if 'rebinding_time' not in parse_result else parse_result['rebinding_time'] + now
        new_lease = DhcpLease(mac, parse_result['yiaddr'], hostname,
                              parse_result['ether_src_address'], server_ip,
                              now, renew_ts, rebind_ts,
                              now + parse_result['lease_time'])

        return new_lease, ''
    #---

    def rebind_lease(self, lease):
        '''Rebind a lease. Just call request_lease() to send the DHCPREQUEST
        and process the DHCPACK'''

        xid = random.randint(1, 0xffffffff)

        logging.info('Protocol machine: Rebind processing for {}/{} server = {}, '
                     'xid = {}'.format(lease.mac(), lease.ip(),
                                       lease.server_ip(), xid))
        
        return self.request_lease(xid, lease.mac(),
                                  lease.hostname(), lease.server_ip(),
                                  lease.ip(), False)
    #---

    def make_dhcp_discover_pkt(self, our_mac, our_hostname, xid):
        '''Use Scapy to build a DHCPDISCOVER packet
        '''

        e = Ether(dst='ff:ff:ff:ff:ff:ff', src=our_mac, type=0x0800)
        i = IP(src='0.0.0.0', dst='255.255.255.255')
        u = UDP(dport=67, sport=68)

        # op = BOOTREQUEST, ciaddr = yiaddr = siaddr = giaddr = 0.0.0.0
        # chaddr = our (client) mac address
        b = BOOTP(op=1, xid=xid, chaddr=utils.mac_address_human_to_bytes(our_mac))

        # 1  = subnet mask
        # 28 = broadcast address
        # 3  = router
        # 15 = domain name
        # 6  = DNS server
        d = DHCP(options=[('message-type', 'discover'),
                          ('hostname', our_hostname),
                          ('lease_time', 0xffffffff),
                          ('param_req_list', 1, 28, 3, 15, 6),
                          'end'])
        p = e/i/u/b/d

        return bytes(p)
    #---

    def make_dhcp_request_pkt(self, our_mac, our_hostname, xid, server_ip_address, requested_ip_address, selecting):
        '''Use Scapy to build a DHCPREQUEST packet. We only employ broadcast
        requests in this program.'''

        e = Ether(dst='ff:ff:ff:ff:ff:ff', src=our_mac, type=0x0800)
        i = IP(src='0.0.0.0', dst='255.255.255.255')
        u = UDP(dport=67, sport=68)

        if selecting:
            # op = BOOTREQUEST, ciaddr = yiaddr = siaddr = giaddr = 0.0.0.0
            # chaddr = our (client) mac address
            b = BOOTP(op=1, xid=xid, chaddr=utils.mac_address_human_to_bytes(our_mac))

            d = DHCP(options=[('message-type', 'request'),
                              ('client_id', b'\x01' + utils.mac_address_human_to_bytes(our_mac)),
                              ('server_id', server_ip_address),
                              ('requested_addr', requested_ip_address),
                              ('hostname', our_hostname),
                              ('param_req_list', 1, 28, 3, 15, 6),
                              'end'])
        else:
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
    #---

    def make_dhcp_release_pkt(self, lease, xid):
        '''Use Scapy to build a DHCPRELEASE packet. This is a unicast from the
        client to the leasing server'''

        e = Ether(dst=lease.server_mac(), src=lease.mac(), type=0x0800)
        i = IP(src=lease.ip(), dst=lease.server_ip())
        u = UDP(dport=67, sport=68)

        # op = BOOTREQUEST, ciaddr = leased (to be released) IP address
        # yiaddr = siaddr = giaddr = 0.0.0.0
        # chaddr = our (client) mac address
        b = BOOTP(op=1, xid=xid,
                  chaddr=utils.mac_address_human_to_bytes(lease.mac()),
                  ciaddr=lease.ip())

        d = DHCP(options=[('message-type', 'release'),
                          ('server_id', lease.server_ip()),
                          ('client_id', b'\x01' + utils.mac_address_human_to_bytes(lease.mac())),
                          'end'])
        p = e/i/u/b/d

        return bytes(p)
    #---

    def parse_dhcp_offer_or_ack(self, pkt, xid):
        '''Use Scapy to parse and obtain the interesting fields from a DHCPACK
        or DHCPOFFER packet received from the network.'''

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

        for key in parse_result:
            logging.debug('Packet parse result: "{}" => "{}"'.format(key, parse_result[key]))

        return parse_result
    #---

#===
