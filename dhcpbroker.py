#!/usr/bin/env python3

import sys
import argparse
from dhcp_client import DhcpClient
from utils import drop_privileges, verify_interface_name, normalize_mac_address
import logging

def main():
    logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s - %(message)s')

    drop_privileges()

    args = parse_command_line_arguments()

    if args.operation == 'new':
        
        mac_address = normalize_mac_address(args.mac)
        if not mac_address:
            sys.exit(-1)
            
        if not verify_interface_name(args.interface):
            sys.exit(-1)
            
        client = DhcpClient(args.interface, args.db)
        (status, errstr, new_lease) = client.new_lease(mac_address,
                                                       args.hostname,
                                                       args.preferred_server)
        if status:
            print('New lease:\n{}'.format(new_lease))
            sys.exit(0)
        else:
            print('Failed to obtain lease for {} ({}): {}'.format(mac_address,
                                                                  args.hostname,
                                                                  errstr))
            sys.exit(-1)
            
    elif args.operation == 'renew':
        pass
    elif args.operation == 'release':
        pass
    elif args.operation == 'view':
        pass
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
    parser_op_new.add_argument('--mac', metavar='<mac>',
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

    renew_client_group.add_argument('--client', metavar='<client>',
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

    release_client_group.add_argument('--client', metavar='<client>',
                                      help='client whole lease to release')
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
