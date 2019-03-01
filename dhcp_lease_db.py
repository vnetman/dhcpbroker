import shelve
from dhcp_lease import DhcpLease

class DhcpLeaseDb(object):
    '''The database of leases that the client obtained. We store a persistent
    copy of this on disk.'''

    def __init__(self, lease_db_file):
        self.lease_db = shelve.open(lease_db_file)

    def persist(self):
        self.lease_db.sync()

    def close(self):
        self.lease_db.close()

    def lookup(self, mac):
        if mac in self.lease_db:
            return self.lease_db[mac]
        return None
