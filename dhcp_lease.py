class DhcpLease(object):
    '''A single DHCP lease'''
    
    def __init__(self):
        self.mac = None          # The client MAC
        self.ip = None           # The IP address that we got
        self.server_ip = None    # The IP address of the server
        self.renew_at = None
        self.rebind_at = None
        self.expire_at = None    # Lease expire datetime
        self.ignored_offers = [] # IP addresses of servers whose offers we did not accept
        
        # Not tracking other DHCP parameters (dns, gateway etc.)
    #---

    def __str__(self):
        print('lease:')
    #---
    
    def mac(self):
        assert self.mac
        return self.mac
