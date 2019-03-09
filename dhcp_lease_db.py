import shelve
import logging
from dhcp_lease import DhcpLease

class DhcpLeaseDb(object):
    '''The database of leases that the client obtained. We store a persistent
    copy of this on disk.'''

    def __init__(self, lease_db_file):
        logging.debug('Opening db file {}'.format(lease_db_file))
        self.lease_db_ = shelve.open(lease_db_file)
    #---

    def add(self, lease):
        logging.debug('Adding lease for {} to db'.format(lease.mac()))
        self.lease_db_[lease.mac()] = lease

    def persist(self):
        logging.debug('Persisting lease db')
        self.lease_db_.sync()
    #---

    def close(self):
        logging.debug('Closing lease db')
        self.lease_db_.close()
    #---

    def lookup(self, mac):
        if mac in self.lease_db_:
            logging.debug('{} found in db'.format(mac))
            return self.lease_db_[mac]

        logging.debug('{} not found in db'.format(mac))
        return None
    #---

    def all_leases(self):
        for mac in self.lease_db_:
            yield (mac, self.lease_db_[mac])
    #---

    def delete_lease_for_mac(self, mac):
        logging.debug('Removing lease for {} from db'.format(mac))
        del self.lease_db_[mac]
    #---
#===
