#!/usr/bin/env python3

import sys
import os
import argparse
from dhcp_client import DhcpClient
from dhcp_lease_db import DhcpLeaseDb
import utils
import logging

def main():
    logging.basicConfig(level=logging.DEBUG,
                        format=' %(asctime)s - %(levelname)s - %(message)s')

    utils.drop_privileges()

    args = parse_command_line_arguments()

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
        
        client = DhcpClient(args.interface, args.db)
        (new_lease, errstr) = client.new_lease(client_mac, args.hostname,
                                               args.preferred_server)
        if new_lease:
            print('New lease:\n{}'.format(new_lease))
            sys.exit(0)
        else:
            print('Failed to obtain lease for {} ({}): {}'.format(mac_address,
                                                                  args.hostname,
                                                                  errstr))
            sys.exit(-1)
            
    elif args.operation == 'rebind':
            
        client = DhcpClient(args.interface, args.db)
        if args.expiring:
            status = True

            (rebound_leases, failed_rebind_leases) = client.rebind_expiring_leases()
            if rebound_leases:
                print('Successfully rebound {} leases:'.format(len(rebound_leases)))
                for l in rebound_leases:
                    print('----------------------------------------')
                    print(l)

            if failed_rebind_leases:
                status = False
                print('Failed to rebind {} leases:'.format(len(failed_rebind_leases)))
                for (l, reason) in failed_rebind_leases:
                    print('-------- {} ---------\n{}\n--------------'.format(reason, l))
        else:
            assert client_mac is not None
            (status, errstr, new_lease) = client.rebind_lease(client_mac)
            if status:
                print('Rebind successful. New lease:')
                print(new_lease)
            else:
                print('Lease rebind failed: {}'.format(errstr))
                                                     
        sys.exit(0 if status else -1)
                
    elif args.operation == 'release':

        client = DhcpClient(args.interface, args.db)
        if args.all:
            client.release_all_leases()
        elif client_mac:
            logging.debug('Attempting to release lease for {}'.format(client_mac))
            if not client.release_lease(client_mac):
                print('Failed to release (non-existent?) lease', file=sys.stderr)
                sys.exit(-1)

        sys.exit(0)

    elif args.operation == 'view':
        for (mac, lease,) in DhcpLeaseDb(args.db).all_leases():
            print(lease)
            print('----------------------------------------')
        sys.exit(0)
        
    else:
        raise ValueError('invalid operation')
#---

def parse_command_line_arguments():
    # new --mac <mac> --hostname <hostname> --interface <interface>
    #                 [--preferred-server <preferred server>] --db <lease db>
    # rebind (--mac <mac> | --expiring) --interface <interface>
    #                 --db <lease db>
    # release (--mac <mac> | --all) --interface <interface>
    #                 --db <lease db>
    # view --db <lease db>

    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(help='Operation', dest='operation')
    subparsers.required = True

    parser_op_new = subparsers.add_parser('new',
                                          help='Obtain new lease')
    
    parser_op_rebind = subparsers.add_parser('rebind',
                                             help='Rebind one or more leases')
    
    parser_op_release = subparsers.add_parser('release',
                                              help='Release one or more leases')
    
    parser_op_view = subparsers.add_parser('view', help='View current leases')

    # Options for 'new'
    parser_op_new.add_argument('--mac', metavar='<mac>', dest='client_mac',
                               help='MAC address to obtain DHCP lease for',
                               required=True)
    parser_op_new.add_argument('--interface', metavar='<interface-name>',
                               help='Interface to work over', required=True)
    parser_op_new.add_argument('--hostname', metavar='<hostname>',
                               help='Host name for simulated client',
                               required=True)
    parser_op_new.add_argument('--db', metavar='<lease_db_file>',
                               help='Db file to store lease in', required=True)

    # If there are multiple DHCP servers in your network, you can use the
    # '--use-server' argument to tell this program which server to prefer.
    # You can use this to, for example, exhaust the leases of a rogue server.
    parser_op_new.add_argument('--preferred-server',
                               metavar='<ip address of DHCP server to use>',
                               required=False)

    # Options for 'rebind'
    rebind_client_group = parser_op_rebind.add_mutually_exclusive_group(required=True)

    rebind_client_group.add_argument('--mac', metavar='<client>', dest='client_mac',
                                     help='specific client to rebind lease for')
    rebind_client_group.add_argument('--expiring',
                                     help='rebind all expiring leases',
                                     action='store_true')
    
    parser_op_rebind.add_argument('--interface', metavar='<interface-name>',
                                  help='Interface to work over', required=True)
    parser_op_rebind.add_argument('--db', metavar='<lease_db_file>',
                                  help='Db file to use', required=True)

    # Options for 'release'
    release_client_group = parser_op_release.add_mutually_exclusive_group(required=True)

    release_client_group.add_argument('--mac', metavar='<client>', dest='client_mac',
                                      help='client whose lease to release')
    release_client_group.add_argument('--all', help='release all leases',
                                      action='store_true')
    
    parser_op_release.add_argument('--interface', metavar='<interface-name>',
                                   help='Interface to work over', required=True)
    parser_op_release.add_argument('--db', metavar='<lease_db_file>',
                                   help='Db file to use', required=True)

    # Options for 'view'
    parser_op_view.add_argument('--db', metavar='<lease_db_file>',
                                help='Db file', required=True)
    
    args = parser.parse_args()

    return args
#---

if __name__ == '__main__':
    main()
