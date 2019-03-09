import time
from dhcp_protocol_machine import DhcpProtocolMachine
from dhcp_lease_db import DhcpLeaseDb
import logging

class DhcpClient(object):
    '''Drive the DHCP main client functionality.'''

    def __init__(self, ifname, lease_db_file):
        self.protocol_machine = DhcpProtocolMachine(ifname)
        self.lease_db = DhcpLeaseDb(lease_db_file)
    #---

    def __del__(self):
        self.lease_db.close()
    #---

    def new_lease(self, mac, hostname, preferred_server):
        existing_lease = self.lease_db.lookup(mac)
        if existing_lease:
            return (None, 'MAC has existing lease')

        logging.info('Client: new lease request for {} ("{}") '
                     '(server = {})'.format(mac, hostname,
                                            preferred_server if preferred_server else 'no preference'))
        
        (lease, errstr) = self.protocol_machine.obtain_new_lease(
            mac, hostname, preferred_server)
        if not lease:
            return (None, errstr)

        logging.info('Client: Adding newly obtained lease to db')

        self.lease_db.add(lease)
        self.lease_db.persist()
        
        return (lease, '')
    #---

    def rebind_expiring_leases(self):
        # We don't support renewal in this program, only rebinding. This is
        # because during renewal, the client is expected to *unicast* the DHCP
        # Request to the server, which in turn will unicast the DHCP Ack to the
        # requester, maybe after first ARPing for the client's unicast IP
        # address. It's bad enough that this program is faking DHCP client
        # functionality on behalf of another client - we don't want to make
        # things worse by faking ARP replies as well. Besides, it is possible
        # that the real client (on behalf of whom we are acting as a DHCP
        # client) may use a different MAC address than the one we told the DHCP
        # server. We try to avoid going down this slippery slope by simply
        # not implementing renewal, and just restrict ourselves to rebind.
        
        successfully_rebound_leases = []
        rebind_failed_leases = []

        now = time.time()
        for (mac, lease) in self.lease_db.all_leases():
            if now < lease.rebind_at():
                # too early
                logging.info('Client: not rebinding {}; too early (rebind time not reached)'.format(mac))
                continue

            if now >= lease.expire_at():
                # too late
                logging.info('Client: not rebinding {}; lease expired'.format(mac))
                rebind_failed_leases.append((lease, 'lease expired'))
                continue

            logging.info('Client: Asking for rebinding {}'.format(mac))
            
            (new_lease, errstr) = self.protocol_machine.rebind_lease(lease)
            if not new_lease:
                logging.info('Client: rebind of {} failed ("{}")'.format(mac, errstr))
                rebind_failed_leases.append((lease, errstr))
            else:
                logging.info('Client: rebind of {} succeeded'.format(mac))
                successfully_rebound_leases.append(new_lease)
                
        # For the successfully rebound leases, remove the old lease from the
        # the db and add the renewed one
        for sl in successfully_rebound_leases:
            logging.info('Client: Deleting & re-adding lease for {} in db'.format(sl.mac))
            self.lease_db.delete_lease_for_mac(sl.mac())
            self.lease_db.add(sl)
            
        return (successfully_rebound_leases, rebind_failed_leases)
    #---

    def rebind_lease(self, client_mac):
        # If we get a specific mac to rebind, we won't check if it needs
        # rebinding
        old_lease = self.lease_db.lookup(client_mac)
        if not old_lease:
            return (False, 'No existing lease for {}'.format(client_mac), None)
        
        logging.info('Client: Asking for rebinding {}'.format(client_mac))
        
        (new_lease, errstr) = self.protocol_machine.rebind_lease(old_lease)
        if not new_lease:
            return (False,
                    'Failed to rebind lease for {}: {}'.format(client_mac, errstr),
                    None)
        
        logging.info('Client: Deleting & re-adding lease for {} in db'.format(client_mac))
        
        self.lease_db.delete_lease_for_mac(client_mac)
        self.lease_db.add(new_lease)
        return (True, '', new_lease)
    #---

    def release_all_leases(self):
        macs = []
        
        for (mac, lease) in self.lease_db.all_leases():
            logging.info('Client: Asking for releasing lease for {}'.format(mac))
            self.protocol_machine.release_lease(lease)
            macs.append(mac)
            
        for mac in macs:
            logging.info('Client: Deleting lease for {} from db'.format(mac))
            self.lease_db.delete_lease_for_mac(mac)
    #---
    
    def release_lease(self, client_mac):
        lease = self.lease_db.lookup(client_mac)
        if not lease:
            logging.info('Client: Cannot release lease for {}: not present in lease db'.format(client_mac))
            return False
        
        logging.info('Client: Asking for releasing lease for {}'.format(lease.mac()))
        self.protocol_machine.release_lease(lease)
        
        logging.info('Client: Deleting lease for {} from db'.format(client_mac))
        self.lease_db.delete_lease_for_mac(client_mac)
        
        return True
    #---
#===


