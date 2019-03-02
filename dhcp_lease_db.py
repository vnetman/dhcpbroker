import shelve
from dhcp_lease import DhcpLease

class DhcpLeaseDb(object):
    '''The database of leases that the client obtained. We store a persistent
    copy of this on disk.'''

    def __init__(self, lease_db_file):
        self.lease_db_ = shelve.open(lease_db_file)

    def add(self, lease):
        self.lease_db_[lease.mac()] = lease

    def persist(self):
        self.lease_db_.sync()

    def close(self):
        self.lease_db_.close()

    def lookup(self, mac):
        if mac in self.lease_db_:
            return self.lease_db_[mac]
        return None

    def all_leases(self):
        for mac in self.lease_db_:
            yield self.lease_db_[mac]
