import os
import re
from socket import socket, AF_PACKET, SOCK_RAW
import subprocess
import psutil
import sys
import struct

def normalize_mac_address(mac):
    try:
        mac_bytes = mac_address_human_to_bytes(mac)
    except ValueError as e:
        print('"{}" cannot be used: {}'.format(mac, str(e)), file=sys.stderr)
        return None
        
    return mac_address_bytes_to_human(mac_bytes)
#--------------------

def verify_interface_name(ifname):
    if not ifname in psutil.net_if_addrs():
        print('"{}" is not a valid interface name; choose one of:'.format(ifname),
              file=sys.stderr)
        for ifname in psutil.net_if_addrs():
            print('{} '.format(ifname), end='', file=sys.stderr)
        print('', file=sys.stderr)
        return False
    
    return True
#--------------------

def set_interface_promiscuous_state(ifname, state):
    # state is 'on' or 'off'
    
    escalate_privileges()

    try:
        cp = subprocess.run(['/sbin/ip', 'link', 'set', ifname, 'promisc', state],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    except Exception as e:
        drop_privileges()
        raise e
    
    drop_privileges()
    
    if cp.returncode != 0:
        print('Failed to set interface {} promiscuous {}: ({}) ({})'.format(
            ifname, state, cp.stdout.decode('utf-8'), cp.stderr.decode('utf-8')),
              flush=True)
        return (False, cp.stdout, cp.stderr)
    else:
        print('Set interface {} promiscuous {}'.format(ifname, state), flush=True)
        return (True, None, None)
#--------------------

def make_raw_socket(interface_name):
    escalate_privileges()
    
    try:
        sock = socket(AF_PACKET, SOCK_RAW)
        sock.bind((interface_name, 0x0800))
    except PermissionError:
        print('Failed to create raw socket. You must run this program with sudo.',
              file=sys.stderr)
        sys.exit(-1)
    except Exception as e:
        drop_privileges()
        raise e
    
    drop_privileges()
    
    return sock
#--------------------

def drop_privileges():
    unpriv_gid = os.getenv('SUDO_GID')
    unpriv_uid = os.getenv('SUDO_UID')
    
    if unpriv_uid and unpriv_gid:
        os.setegid(int(unpriv_gid))
        os.seteuid(int(unpriv_uid))
        os.umask(0o22)
#--------------------

def escalate_privileges():
    # If the SUDO_UID and SUDO_GID env vars are not set, we won't be able
    # to drop privileges later on, so we won't do anything here unless these
    # are set. IOW the program  has to be started with sudo.
    
    unpriv_gid = os.getenv('SUDO_GID')
    unpriv_uid = os.getenv('SUDO_UID')
    
    if unpriv_uid and unpriv_gid:
        os.seteuid(0)
        os.setegid(0)    
#--------------------

def mac_address_human_to_bytes(mac_address_human):
    for sep in (':', '-',):
        pieces = mac_address_human.split(sep)
        if len(pieces) == 6:
            # xx:xx:xx:xx:xx:xx
            # xx-xx-xx-xx-xx-xx
            return bytes([int(m, 16) for m in pieces])
    
    pieces = mac_address_human.split('.')
    if len(pieces) == 3:
        # xxxx.xxxx.xxxx
        mac_address_human = mac_address_human.replace('.', '')
        # fall through to xxxxxxxxxxxx case
    
    if len(mac_address_human) != 12:
        raise ValueError('"{}" is not a valid ethernet MAC address'.format(mac_address_human))

    return bytes([int(m, 16) for m in re.findall(r'..', mac_address_human)])
#--------------------

def mac_address_bytes_to_human(mac_address_bytes):
    octets = struct.unpack('6B', mac_address_bytes)
    return ':'.join(['{:02X}'.format(octet) for octet in octets])
#--------------------

if __name__ == '__main__':
    import struct
    
    mac_address = '000c.1122.33ee'
    
    (status, result) = mac_address_human_to_bytes(mac_address)

    if status:
        print(mac_address_bytes_to_human(result))

    else:
        print('Failed to translate {}'.format(mac_address))
