#!/usr/bin/env python
# -*- coding: utf-8 -*-
#  loopia-dyndns.py - A dynamic DNS updater using the Loopia API
#  Copyright (C) 2013  Stefan Wold <ratler@stderr.eu>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.


import argparse
import sys
import platform
import netifaces as ni

try:
    import xmlrpc.client as client # python 3
except ImportError:
    import xmlrpclib as client # python 2

LOOPIA_API_URL = 'https://api.loopia.se/RPCSERV'

INTERFACES = {
    'Linux': 'eth0',
    'Darwin': 'en0',
    'Windows': 'ethernet_0'
}

VERBOSE = False

__VERSION__ = "0.2"

try:
    DEFAULT_IFACE4 = INTERFACES[platform.system()]
except KeyError:
    DEFAULT_IFACE4 = None


def main():
    global VERBOSE

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-u',
        '--username',
        required=True,
        help='Loopia API username.'
    )
    parser.add_argument(
        '-p',
        '--password',
        required=True,
        help='Loopia API password.'
    )
    parser.add_argument(
        '-i',
        '--interface4',
        default=DEFAULT_IFACE4,
        help='Interface to automatically grab ipv4 address from (default eth0).'
    )
    parser.add_argument(
        '-n',
        '--interface6',
        help='Interface to automatically grab ipv6 address from.'
    )
    parser.add_argument(
        '-4',
        '--ipv4',
        help='Manually update ipv4 address to this ip.'
    )
    parser.add_argument(
        '-6',
        '--ipv6',
        help='Manually update ipv6 address to this ip.'
    )
    parser.add_argument(
        '-d',
        '--domain',
        required=True,
        help='The domain to update when the ip has changed.'
    )
    parser.add_argument(
        '-v',
        '--verbose',
        help='Increase output verbosity.',
        action="store_true"
    )
    parser.add_argument(
        '-V',
        '--version',
        action='version',
        version="loopia-dyndns.py version {}".format(__VERSION__)
    )
    args = parser.parse_args()

    if args.verbose:
        VERBOSE = True

    username = args.username
    password = args.password
    domain = args.domain

    ip4_address = get_my_ipv4(args)
    ip6_address = get_my_ipv6(args)

    if ip4_address or ip6_address:
        update_ip_info(username, password, domain, ip4_address, ip6_address)
    else:
        error_exit("No ip address found! See loopia-dynds-py -h for help.")


def verbose_message(message):
    if VERBOSE:
        print message


def error_exit(message):
    print message
    sys.exit(1)


def get_rpc_client():
    return client.ServerProxy(uri=LOOPIA_API_URL, encoding='utf-8')


def get_my_ipv4(args):
    if args.ipv4:
        return args.ipv4
    try:
        if args.interface4:
            # TODO(Ratler): Properly iterate and find a valid ipv4 address, this doesn't always work
            return ni.ifaddresses(args.interface4)[ni.AF_INET][0]['addr']
        else:
            return None
    except ValueError:
        error_exit("ERROR: Invalid interface " + args.interface4)
    except KeyError:
        error_exit("ERROR: No IPV4 address found on interface {}".format(args.interface4))
    except IndexError:
        error_exit("ERROR: Failed to determine IPV4 address on interface {}, try using option -4 <ipv4 address>".format(args.interface4))


def get_my_ipv6(args):
    if args.ipv6:
        return args.ipv6
    try:
        if args.interface6:
            # TODO(Ratler): Properly iterate and find a valid ipv6 address, this doesn't always work
            return ni.ifaddresses(args.interface6)[ni.AF_INET6][1]['addr']
        else:
            return None
    except ValueError:
        error_exit("ERROR: Invalid interface " + args.interface6)
    except KeyError:
        error_exit("ERROR: No IPV6 address found on interface {}".format(args.interface6))
    except IndexError:
        error_exit("ERROR: Failed to determine IPV6 address on interface {}, try using option -6 <ipv6 address>".format(args.interface6))


def update_ip_info(username, password, domain, ip4_address, ip6_address):
    old_ipv4, old_ipv6 = None, None
    (subdomain, domain) = get_domain_tuple(domain)
    zone_records = get_rpc_client().getZoneRecords(username, password, domain, subdomain)

    if isinstance(zone_records, list) and len(zone_records) and zone_records[0] == "AUTH_ERROR":
        error_exit("Wrong API username or password!")
    elif isinstance(zone_records, list) and len(zone_records) == 0:
        error_exit("Domain {}.{} not found.".format(subdomain, domain))

    for record in zone_records:
        if ip6_address and (record['type'] == 'AAAA') and (ip6_address != record['rdata']):
            old_ipv6 = record['rdata']
            record['rdata'] = ip6_address
        if ip4_address and (record['type'] == 'A') and (ip4_address != record['rdata']):
            old_ipv4 = record['rdata']
            record['rdata'] = ip4_address

        if (old_ipv4 is not None) or (old_ipv6 is not None):
            get_rpc_client().updateZoneRecord(username, password, domain, subdomain, record)
            if old_ipv4 is not None:
                verbose_message("Zone {}.{} updated. Old IPV4: {}, New IPV4: {}".format(
                    subdomain, domain, old_ipv4, ip4_address))
            if old_ipv6 is not None:
                verbose_message("Zone {}.{} updated. Old IPV6: {}, New IPV6: {}".format(
                    subdomain, domain, old_ipv6, ip6_address))


def get_domain_tuple(domain):
    count = domain.count('.')

    if not count:
        error_exit("Invalid domain {}".format(domain))
    if count == 1:
        subdomain = '@'
    else:
        domain_items = domain.split('.')
        domain = '.'.join([domain_items.pop(-2), domain_items.pop()])
        subdomain = '.'.join(domain_items)

    return subdomain, domain


if __name__ == '__main__':
    main()
