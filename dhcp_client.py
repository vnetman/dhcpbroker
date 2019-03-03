from dhcp_protocol_machine import DhcpProtocolMachine
from dhcp_lease_db import DhcpLeaseDb

class DhcpClient(object):
    '''Drive the DHCP main client functionality.'''

    def __init__(self, ifname, lease_db_file):
        self.protocol_machine = DhcpProtocolMachine(ifname)
        self.lease_db = DhcpLeaseDb(lease_db_file)

    def __del__(self):
        self.lease_db.close()

    def new_lease(self, mac, hostname, preferred_server):
        existing_lease = self.lease_db.lookup(mac)
        if existing_lease:
            return (False, 'MAC has existing lease', None)
        
        (status, errstr, lease) = self.protocol_machine.obtain_new_lease(
            mac, hostname, preferred_server)
            
        if not status:
            return (False, errstr, None)

        self.lease_db.add(lease)
        self.lease_db.persist()
        
        return (True, None, lease)

    def renew_expiring_leases(self):
        successfully_renewed_leases = []
        renewal_failed_leases = []
        return (False, successfully_renewed_leases, renewal_failed_leases)

    def renew_lease(self, client_mac):
        new_lease = None
        return (False, 'not implemented yet', new_lease) 

    def release_all_leases(self):
        
    
    def release_lease(self, client):
        pass

#--------------------

