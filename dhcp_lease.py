import utils

class DhcpLease(object):
    '''A single DHCP lease'''
    
    def __init__(self, mac, ip, server_mac, server_ip, leased_at, renew_at,
                 rebind_at, expire_at, ignored_offers):
        
        self.mac_ = mac               # The client MAC
        self.ip_ = ip                 # The IP address that we got
        self.server_mac_ = server_mac # The MAC address of the server
        self.server_ip_ = server_ip   # The IP address of the server
        self.leased_at_ = leased_at
        self.renew_at_ = renew_at
        self.rebind_at_ = rebind_at
        self.expire_at_ = expire_at
        self.ignored_offers_ = []  # IP addresses of servers whose offers we did not accept
        for io in ignored_offers:
            self.ignored_offers_.append(io)
        
        # Not tracking other DHCP parameters (dns, gateway etc.)
    #---
            
    def __str__(self):
        strep  = '     Client MAC: {}\n'
        strep += '      Client IP: {}\n'
        strep += '         Server: {} ({})\n'
        strep += '      Leased at: {}\n'
        strep += '      Expire at: {}\n'
        strep += '       Renew at: {}\n'
        strep += '      Rebind at: {}\n'
        strep += 'Ignored servers: {}\n'
        
        return strep.format(self.mac_, self.ip_, self.server_ip_, self.server_mac_,
                            utils.epoch_to_printable_localtime(self.leased_at_),
                            utils.epoch_to_printable_localtime(self.expire_at_),
                            utils.epoch_to_printable_localtime(self.renew_at_),
                            utils.epoch_to_printable_localtime(self.rebind_at_),
                            self.ignored_offers_)
    #---
    
    def mac(self):
        assert self.mac_
        return self.mac_
