import time
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
        # Only renew leases past the renewal time, but not past the rebinding
        # time. For leases past the rebind time, we'll fail and ask the user
        # to release the lease and get a new one.
        successfully_renewed_leases = []
        renewal_failed_leases = []

        now = time.time()
        for (mac, lease) in self.lease_db.all_leases():
            if now < lease.renew_at():
                continue
            if now > lease.rebind_at():
                renewal_failed_leases.append((lease, 'past rebind time',))
                continue
            
            (new_lease, errstr) = self.protocol_machine.renew_lease(lease)
            if not new_lease:
                renewal_failed_leases.append((lease, errstr))
            else:
                successfully_renewed_leases.append(new_lease)
                
        # For the successfully renewed leases, remove the old lease from the
        # the db and add the renewed one
        for sl in successfully_renewed_leases:
            self.lease_db.delete_lease_for_mac(sl.mac())
            self.lease_db.add(sl)
            
        return (successfully_renewed_leases, renewal_failed_leases)

    def renew_lease(self, client_mac):
        # If we get a specific mac to renew, we won't check if it needs
        # renewing
        old_lease = self.lease_db.lookup(client_mac)
        if not old_lease:
            return (False, 'No existing lease for {}'.format(client_mac), None)
        
        (new_lease, errstr) = self.protocol_machine.renew_lease(old_lease)
        if not new_lease:
            return (False,
                    'Failed to renew lease for {}: {}'.format(client_mac, errstr),
                    None)
        
        self.lease_db.delete_lease_for_mac(client_mac)
        self.lease_db.add(new_lease)
        return (True, '', new_lease) 

    def release_all_leases(self):
        macs = []
        for (mac, lease) in self.lease_db.all_leases():
            self.protocol_machine.release_lease(lease)
            macs.append(mac)
        for mac in macs:
            self.lease_db.delete_lease_for_mac(mac)
    
    def release_lease(self, client_mac):
        lease = self.lease_db.lookup(client_mac)
        if not lease:
            return False
        
        self.protocol_machine.release_lease(lease)
        self.lease_db.delete_lease_for_mac(client_mac)
        
        return True

#--------------------

