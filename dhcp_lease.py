import time
import utils

class DhcpLease(object):
    '''A single DHCP lease'''
    
    def __init__(self, mac, ip, hostname, server_mac, server_ip, leased_at,
                 renew_at, rebind_at, expire_at, ignored_offers):
        
        self.mac_ = mac               # The client MAC
        self.hostname_ = hostname     # The client's hostname
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
        strep  = '       Hostname: {}\n'
        strep += '     Client MAC: {}\n'
        strep += '      Client IP: {}\n'
        strep += '         Server: {} ({})\n'
        strep += '      Leased at: {}\n'
        strep += '      Expire at: {}\n'
        strep += '       Renew at: {} {}\n'
        strep += '      Rebind at: {} {}\n'
        strep += 'Ignored servers: {}\n'
        
        return strep.format(self.hostname_, self.mac_, self.ip_, self.server_ip_, self.server_mac_,
                            utils.epoch_to_printable_localtime(self.leased_at_),
                            utils.epoch_to_printable_localtime(self.expire_at_),
                            utils.epoch_to_printable_localtime(self.renew_at()),
                            '(calculated)' if not self.renew_at_ else '',
                            utils.epoch_to_printable_localtime(self.rebind_at()),
                            '(calculated)' if not self.rebind_at_ else '',
                            self.ignored_offers_)
    #---
    
    def mac(self):
        return self.mac_
    #---

    def ip(self):
        return self.ip_
    #---

    def server_mac(self):
        return self.server_mac_
    #---

    def server_ip(self):
        return self.server_ip_
    #---

    def renew_at(self):
        # If the server provided a value, use it. Otherwise calculate it.
        if self.renew_at_:
            return self.renew_at_
        else:
            x = self.leased_at_
            y = self.expire_at_
            return x + (((y - x) * 50) // 100)
    #---

    def rebind_at(self):
        # If the server provided a value, use it. Otherwise calculate it.
        if self.rebind_at_:
            return self.rebind_at_
        else:
            x = self.leased_at_
            y = self.expire_at_
            return x + (((y - x) * 87) // 100)
    #---

    def expire_at(self):
        return self.expire_at_
    #---

    def leased_at(self):
        return self.leased_at_
    #---

    def hostname(self):
        return self.hostname_
    #---
#===    
