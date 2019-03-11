#!/usr/bin/env python3

'''dhcpbroker.py

Restrictions and caveats:

(1) Ethernet interfaces only.
(2) Linux only.
(3) Needs to run as sudo, because it needs access to raw sockets, and it needs 
    to be able to set the network interface to promiscuous mode.
(4) Lease extension works with No support for Renewing DHCP leases; only Rebinds are supported. Renew 
    works by means of unicast to the DHCP server
(5) Not tested with relay agents
'''

import sys
import os
import argparse
from dhcp_client import DhcpClient
from dhcp_lease_db import DhcpLeaseDb
import utils
import logging

def main():
    '''Application entry point.
    '''

    # Don't run as root unless we have to (see escalate_privileges())
    utils.drop_privileges()

    args = parse_command_line_arguments()

    logging.basicConfig(level=args.loglevel,
                        format=' %(asctime)s - %(levelname)s - %(message)s')

    # If there is a mac address argument on the command line, "normalize" it to
    # our standard form (XX:XX:XX:XX:XX:XX)
    try:
        client_mac = utils.normalize_mac_address(args.client_mac)
        if not client_mac:
            sys.exit(-1)
    except AttributeError:
        client_mac = None

    # If there is an interface name on the command line, see if it is legit.
    try:
        if not utils.verify_interface_name(args.interface):
            sys.exit(-1)
    except AttributeError:
        pass

    # Verify the "db" argument on the command line. All operation modes use
    # the db argument
    if os.path.exists(args.db):
        if not os.path.isfile(args.db):
            print('"{}" is not a file'.format(args.db),
                  file=sys.stderr)
            sys.exit(-1)
    else:
        # For all operations other than 'new', the lease db file has to exist
        if args.operation != 'new':
            print('db file "{}" does not exist'.format(args.db),
                  file=sys.stderr)
            sys.exit(-1)

    if args.operation == 'new':
        handle_new_lease(client_mac, args.hostname, args.preferred_server,
                         args.interface, args.db)

    elif args.operation == 'rebind':
        handle_rebind(client_mac, args.expiring, args.interface, args.db)

    elif args.operation == 'release':
        handle_release(client_mac, args.all, args.interface, args.db)

    elif args.operation == 'view':
        for (mac, lease,) in DhcpLeaseDb(args.db).all_leases():
            print(lease)
            print('----------------------------------------')
        sys.exit(0)

    else:
        raise ValueError('invalid operation')
#---

def parse_command_line_arguments():
    '''Command line switches:

    [--info | --debug]
    
    new --mac <mac> --hostname <hostname> --interface <interface>
                    [--preferred-server <preferred server>] --db <lease db>
    rebind (--mac <mac> | --expiring) --interface <interface>
                    --db <lease db>
    release (--mac <mac> | --all) --interface <interface>
                    --db <lease db>
    view --db <lease db>'''

    parser = argparse.ArgumentParser()

    # Logging options, at the top level
    logging_group = parser.add_mutually_exclusive_group()
    logging_group.add_argument('--info', help='log informational lines',
                               action='store_const', dest='loglevel',
                               const=logging.INFO, default=logging.CRITICAL)
    logging_group.add_argument('--debug', help='log debugging lines',
                               action='store_const', dest='loglevel',
                               const=logging.DEBUG)

    # Sub-parsers for new, rebind, release and view
    subparsers = parser.add_subparsers(help='Operation', dest='operation')
    subparsers.required = True

    op_new = subparsers.add_parser('new', help='Obtain new lease')
    op_rebind = subparsers.add_parser('rebind',
                                      help='Rebind one or more leases')
    op_release = subparsers.add_parser('release',
                                       help='Release one or more leases')
    op_view = subparsers.add_parser('view', help='View current leases')

    # Options for 'new'
    op_new.add_argument('--mac', metavar='<mac>', dest='client_mac',
                        help='MAC address to obtain DHCP lease for',
                        required=True)
    op_new.add_argument('--interface', metavar='<interface-name>',
                        help='Interface to work over', required=True)
    op_new.add_argument('--hostname', metavar='<hostname>',
                        help='Host name for simulated client',
                        required=True)
    op_new.add_argument('--db', metavar='<lease_db_file>',
                        help='Db file to store lease in', required=True)

    # If there are multiple DHCP servers in your network, you can use the
    # '--use-server' argument to tell this program which server to prefer.
    # You can use this to, for example, exhaust the leases of a rogue server.
    op_new.add_argument('--preferred-server',
                        metavar='<ip address of DHCP server to use>',
                        required=False)

    # Options for 'rebind'
    rebind_host_group = op_rebind.add_mutually_exclusive_group(required=True)

    rebind_host_group.add_argument('--mac', metavar='<client>',
                                   dest='client_mac',
                                   help='specific client to rebind lease for')
    rebind_host_group.add_argument('--expiring',
                                   help='rebind all expiring leases',
                                   action='store_true')

    op_rebind.add_argument('--interface', metavar='<interface-name>',
                           help='Interface to work over', required=True)
    op_rebind.add_argument('--db', metavar='<lease_db_file>',
                           help='Db file to use', required=True)

    # Options for 'release'
    release_host_group = op_release.add_mutually_exclusive_group(required=True)

    release_host_group.add_argument('--mac', metavar='<client>',
                                    dest='client_mac',
                                    help='client whose lease to release')
    release_host_group.add_argument('--all', help='release all leases',
                                    action='store_true')

    op_release.add_argument('--interface', metavar='<interface-name>',
                            help='Interface to work over', required=True)
    op_release.add_argument('--db', metavar='<lease_db_file>',
                            help='Db file to use', required=True)

    # Options for 'view'
    op_view.add_argument('--db', metavar='<lease_db_file>', help='Db file',
                         required=True)

    args = parser.parse_args()

    return args
#---

def handle_new_lease(client_mac, hostname, preferred_server, interface, db):
    '''Obtain a new lease, given the command-line arguments.
    Create a DhcpClient object and invoke its new_lease() method.'''

    client = DhcpClient(interface, db)
    (new_lease, errstr) = client.new_lease(client_mac, hostname,
                                           preferred_server)
    if new_lease:
        print('New lease:\n{}'.format(new_lease))
        sys.exit(0)
    else:
        print('Failed to obtain lease for {} ({}): '
              '{}'.format(client_mac, hostname, errstr))
        sys.exit(-1)
#---

def handle_rebind(client_mac, expiring, interface, db):
    '''Rebind a lease, given the command-line arguments.
    Create a DhcpClient object and invoke one of its rebind_xxx() methods.'''

    client = DhcpClient(interface, db)

    if expiring:
        status = True

        successes, failures = client.rebind_expiring_leases()
        
        if successes:
            print('Successfully rebound {} leases:'.format(len(successes)))
            for l in rebound_leases:
                print('----------------------------------------\n{}'.format(l))

        if failures:
            status = False
            print('Failed to rebind {} leases:'.format(len(failures)))
            for (l, reason) in failed_rebind_leases:
                print('-------- {} ---------\n{}\n'.format(reason, l))
                
    else:
        assert client_mac is not None
        
        new_lease, errstr = client.rebind_lease(client_mac)
        if new_lease:
            print('Rebind successful. New lease:')
            print(new_lease)
            status = True
        else:
            print('Lease rebind failed: {}'.format(errstr))
            status = False

    sys.exit(0 if status else -1)
#---

def handle_release(client_mac, all_client_macs, interface, db):
    '''Release one or more leases, as indicated by command line arguments.
    Create a DhcpClient object and call one of its release_xxx methods.'''
    
    client = DhcpClient(interface, db)
    
    if all_client_macs:
        client.release_all_leases()

    elif client_mac:
        logging.info('Attempting to release lease for {}'.format(client_mac))
        if not client.release_lease(client_mac):
            print('Failed to release (non-existent?) lease', file=sys.stderr)
            sys.exit(-1)

    sys.exit(0)
#---

if __name__ == '__main__':
    main()
