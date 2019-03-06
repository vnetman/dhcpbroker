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
        pass

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
            
    elif args.operation == 'renew':
            
        client = DhcpClient(args.interface, args.db)
        if args.expiring:
            (successfully_renewed_leases, renewal_failed_leases) = client.renew_expiring_leases()
            print('Successfully renewed {} lease(s):'.format(len(successfully_renewed_leases)))
            for l in successfully_renewed_leases:
                print(l)
                
            status = True
            print('Failed to renew {} lease(s):'.format(len(renewal_failed_leases)))
            for (l, reason) in renewal_failed_leases:
                status = False
                print('-------- {} ---------\n{}\n--------------'.format(reason, l))
        elif args.client:
            (status, errstr, new_lease) = client.renew_lease(args.client)
            if status:
                print('Renewal successful. New lease:')
                print(new_lease)
            else:
                print('Lease renewal failed: {}'.format(errstr))
        else:
            raise ValueError('Neither "expiring" nor "client" was specified')
                                                     
        sys.exit(0 if status else -1)
                
    elif args.operation == 'release':
        if not os.path.isfile(args.db):
            print('"{}": no such file'.format(args.db), file=sys.stderr)
            sys.exit(-1)

        client = DhcpClient(args.interface, args.db)
        if args.all:
            client.release_all_leases()
        elif args.client:
            logging.debug('Attempting to release lease for {}'.format(args.client))
            if not client.release_lease(args.client):
                print('Failed to release (non-existent?) lease', file=sys.stderr)
                sys.exit(-1)

        sys.exit(0)
    elif args.operation == 'view':
        if not os.path.isfile(args.db):
            print('"{}": no such file'.format(args.db), file=sys.stderr)
            sys.exit(-1)
        for (mac, lease,) in DhcpLeaseDb(args.db).all_leases():
            print(lease)
        sys.exit(0)
    else:
        raise ValueError('invalid operation')
#--------------------

def parse_command_line_arguments():
    # new --mac <mac> --hostname <hostname> --interface <interface>
    #                 [--preferred-server <preferred server>] --db <lease db>
    # renew (--client <client> | --expiring) --interface <interface>
    #                 --db <lease db>
    # release (--client <client> | --all) --interface <interface>
    #                 --db <lease db>
    # view --db <lease db>

    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(help='Operation', dest='operation')
    subparsers.required = True

    parser_op_new = subparsers.add_parser('new',
                                          help='Obtain new lease')
    
    parser_op_renew = subparsers.add_parser('renew',
                                            help='Renew one or more leases')
    
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

    # Options for 'renew'
    renew_client_group = parser_op_renew.add_mutually_exclusive_group()

    renew_client_group.add_argument('--client', metavar='<client>', dest='client_mac',
                                    help='specific client to renew lease for')
    renew_client_group.add_argument('--expiring',
                                    help='renew all expiring leases',
                                    action='store_true')
    
    parser_op_renew.add_argument('--interface', metavar='<interface-name>',
                                 help='Interface to work over', required=True)
    parser_op_renew.add_argument('--db', metavar='<lease_db_file>',
                                 help='Db file to use', required=True)

    # Options for 'release'
    release_client_group = parser_op_release.add_mutually_exclusive_group()

    release_client_group.add_argument('--client', metavar='<client>', dest='client_mac',
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
#--------------------

if __name__ == '__main__':
    main()
