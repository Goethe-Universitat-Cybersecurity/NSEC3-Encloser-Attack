#!/usr/bin/env python
import argparse
import dns.dnssec
import dns.zone
import dns.rrset
from dns.rdtypes.dnskeybase import Flag

import lib.config
import lib.keys
import lib.nsec3
import lib.dnssec

import os


NSD_CONF = """#
# nsd.conf -- the NSD(8) configuration file, nsd.conf(5).
#
# Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
#
# See LICENSE for the license.
#
{}
"""

NAMED_CONF = """trust-anchors {{
{}}};

options {{
    dnssec-validation yes;
}};
"""


def get_keypair(keys_dir, name, size, algorithm):
    ksk_path = os.path.join(keys_dir, name + '.ksk.pem')
    zsk_path = os.path.join(keys_dir, name + '.zsk.pem')
    try:
        ksk_privkey = lib.keys.load_key_from_file(ksk_path)
        zsk_privkey = lib.keys.load_key_from_file(zsk_path)
    except:
        print(f'Could not load keys {ksk_path}, {zsk_path} for zone {name}, did you generate them?')
        return None
    ksk_dnskey = dns.dnssec.make_dnskey(
            ksk_privkey.public_key(),
            algorithm,
            Flag.ZONE | Flag.SEP,
            3)
    zsk_dnskey = dns.dnssec.make_dnskey(
            zsk_privkey.public_key(),
            algorithm,
            Flag.ZONE,
            3)
    return [(ksk_privkey, ksk_dnskey), (zsk_privkey, zsk_dnskey)]


def get_nsec3param(zone):
    nsec3 = zone['nsec3']
    nsec3_salt = lib.nsec3.decode_salt(nsec3['salt'])

    rdata_nsec3param = dns.dnssec.NSEC3PARAM(
            'IN', 'NSEC3PARAM',
            nsec3['algorithm'],
            0, # Flags must be zero
            nsec3['iterations'],
            nsec3_salt,
            )
    return rdata_nsec3param


def get_ns_rrsets(zone):
    """
    Generates NS and accompanying records from a zone config
    """
    origin = zone['origin']
    ttl = zone['ttl'] # FIXME ttl
    rrsets = []
    for ns_entry in zone['ns']:
        #print(ns_entry)
        domain = ns_entry['ns']
        ips = ns_entry['ip']
        rrset_ns = dns.rrset.from_text(origin, ttl, 'IN', 'NS', domain)
        rrsets.append(rrset_ns)
        if type(ips) is str:
            ips = [ips]
        rrset_a = dns.rrset.from_text(domain, ttl, 'IN', 'A', *ips)
        rrsets.append(rrset_a)
        #print(rrset_ns)
    return rrsets


def get_zone_text(zone, keys=None):
    """
    Generates the zone text with SOA, NS and nameserver records
    """
    origin = zone['origin']
    ttl = zone['ttl'] # FIXME ttl
    soa = zone['soa']
    zone_text = f"{origin} {ttl} IN SOA {soa}\n"
    for rrset in get_ns_rrsets(zone):
        zone_text += rrset.to_text() + '\n'
    # TODO self-signed DS record
    if keys is not None:
        ds = dns.dnssec.make_ds(
                origin,
                keys[0][1],
                dns.dnssec.DSDigest.SHA1, # TODO
                policy=dns.dnssec.allow_all_policy
        )
        rrset_ds = dns.rrset.from_rdata(
                origin,
                ttl,
                ds,
        )
        zone_text += rrset_ds.to_text() + '\n'
    # end self-signed
    return zone_text


def gen_zone(zone, keys):
    name = zone['name']
    origin = zone['origin']
    # TODO relative
    keysize = zone['keysize']
    nsec3 = zone['nsec3']
    rrsets = zone['rrsets']

    nsec3_tight = nsec3['tight']
    if nsec3_tight:
        print(f'  Forging tight NSEC3 records for zone {name}')
    
    rdata_nsec3param = get_nsec3param(zone)

    # TODO hardcoded
    inception = '20230101000000'
    expiration = '20330101000000'
    relativize = False
    
    zone_text = get_zone_text(zone, keys=keys) # TODO keys parameter
    #print(f'origin {origin}')
    #print(zone_text)
    z = dns.zone.from_text(zone_text, origin, relativize=relativize)

    with z.writer() as txn:
        for rrset_any in rrsets:
            if type(rrset_any) == list:
                rrset_text = rrset_any
                n, ttl, c, t, d = rrset_text
                if type(d) == str:
                    d = [d]
                rrset = dns.rrset.from_text_list(n, ttl, c, t, d)
            else: # TODO elif type == rrset
                rrset = rrset_any
            #print(f' + {rrset}')
            txn.add(rrset)
        lib.dnssec.sign_zone(
                z,
                txn,
                keys,
                inception=inception,
                expiration=expiration,
                nsec3=rdata_nsec3param,
                nsec3_tight=nsec3_tight,
                )
        return z


def gen_zones(config, keys_dir='keys'):
    if not os.path.isdir(keys_dir):
        print(f'Error: Keys directory {keys_dir} not found')
        return
    zones = config['zones']

    # Step 1: organize zones into tree
    zone_map = {}
    zone_tree = {}
    leaf_nodes = set()
    nr_unprocessed = len(zones)
    for zone in zones:
        name = zone['name']
        zone_map[name] = zone
        zone_tree[name] = []
        leaf_nodes.add(name)
    for zone in zones:
        if 'parent' not in zone or zone['parent'] == None or zone['parent'] == '':
            # Root zone
            zone['parent'] = None
            pass
        else:
            parent = zone['parent']
            if parent not in zone_tree:
                print(f'Error: Parent {parent} of zone {name} not found') 
                # Delete parent so that it does not cause any issues later
                zone['parent'] = None
                continue
            if parent in leaf_nodes:
                leaf_nodes.remove(parent)
            zone_tree[parent].append(zone['name'])
    
    # Step 2: Continually process leaf nodes
    dns_zones = {}

    while nr_unprocessed > 0:
        if len(leaf_nodes) == 0:
            print(f'Error: Circular zone tree')
            break
        next_zone = leaf_nodes.pop()
        zone = zone_map[next_zone]
        name = zone['name']
        origin = zone['origin']
        parent = zone['parent']
        keysize = zone['keysize']
        algorithm = dns.dnssec.RSASHA1NSEC3SHA1 # TODO
        ttl = zone['ttl'] # TODO
        relativize = False # TODO

        # Obtain keys
        keys = get_keypair(keys_dir, name, keysize, algorithm)
        if not keys:
            print(f'Aborting')
            break

        # Process zone
        print(f'Generating {name} with origin {origin}')
        dns_zone = gen_zone(zone, keys)
        dns_zones[name] = dns_zone

        if parent is None:
            pass
        else:
            # Add records to parent zone
            ds = dns.dnssec.make_ds(
                    origin,
                    keys[0][1],
                    dns.dnssec.DSDigest.SHA1, # TODO
                    policy=dns.dnssec.allow_all_policy
            )
            rrset_ds = dns.rrset.from_rdata(
                    origin,
                    ttl,
                    ds,
            )
            rrset_nsec3param = dns.rrset.from_rdata(
                    origin,
                    ttl,
                    get_nsec3param(zone),
            )
            rrsets_ns = get_ns_rrsets(zone)

            print(f'  Adding {origin} records to {parent}')
            zone_map[parent]['rrsets'].append(rrset_ds)
            zone_map[parent]['rrsets'].append(rrset_nsec3param)
            zone_map[parent]['rrsets'] += rrsets_ns

            zone_tree[parent].remove(name)
            if len(zone_tree[parent]) == 0:
                leaf_nodes.add(parent)
        nr_unprocessed -= 1
    return dns_zones


def export_zones(zones, output_dir='keys'):
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    # TODO hardcoded
    relativize = False

    for name in zones:
        dns_zone = zones[name]
        # Write zonefile
        filename = name + '.zone'
        zonefile = os.path.join(output_dir, filename)
        print(f'Writing Zonefile {zonefile}')
        with open(zonefile, 'w') as f:
            dns_zone.to_file(f, relativize=relativize, want_comments=True, want_origin=True)


def export_configs(zones, config, output_dir='zones', only_root=False):
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    
    nsd_conf_s = ''
    named_conf_s = ''
    path_prefix = config['default']['path_prefix']

    for zone_config in config['zones']:
        name = zone_config['name']
        origin = zone_config['origin']

        # TODO replace this with proper path parsing
        if len(path_prefix) > 0:
            if path_prefix[-1] != '/':
                path_prefix += '/'

        nsd_conf_s += 'zone:\n'
        nsd_conf_s += f'    name: "{origin}"\n'
        nsd_conf_s += f'    zonefile: {path_prefix}{name}.zone\n'

        if only_root and 'parent' in zone_config:
            parent = zone_config['parent']
            # Skip nodes where some parent is known
            if parent in zones:
                continue
            elif not(parent is None or parent == ''):
                print(f'Warning: zone {name} has unknown parent {parent}, exporting to auth files')

        if name not in zones:
            continue
        z = zones[name]
        with z.reader() as txn:
            dnskeys = txn.get(origin, 'dnskey')

        # named.conf
        for dnskey in dnskeys:
            named_conf_s += f'    {origin} static-key {dnskey.flags} {dnskey.protocol} {dnskey.algorithm} "{dns.rdata._base64ify(dnskey.key)}";\n'

    # nsd.conf
    print(f'Generating (partial) nsd.conf')
    config_text = NSD_CONF.format(nsd_conf_s)
    filename = 'nsd.conf'
    config_file = os.path.join(output_dir, filename)
    with open(config_file, 'w') as f:
        f.write(config_text)

    # named.conf
    print(f'Generating named.conf')
    config_text = NAMED_CONF.format(named_conf_s)
    filename = 'named.conf'
    config_file = os.path.join(output_dir, filename)
    with open(config_file, 'w') as f:
        f.write(config_text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            description = 'Generates the Zonefiles for the NSEC3 attack based on a configuration',
            )
    parser.add_argument('config', nargs='?', default='config.json', help='config file')
    parser.add_argument('-k', '--keys', default='keys', help='keys directory, from which the key files are loaded')
    parser.add_argument('-o', '--output', default='zones', help='output directory, into which the zonefiles are exported')
    parser.add_argument('-c', action='store_true', help='additionally generate configuration files')
    args = parser.parse_args()
    config_file = args.config
    keys_dir = args.keys
    zones_dir = args.output
    enable_export_configs = args.c
    print(f'Creating zonefiles from {config_file}')

    config = lib.config.load_config(config_file)
    if 'zones' not in config:
        print('Error: No zones found in config, exiting.')
        exit(-1) 

    zones = gen_zones(config, keys_dir=keys_dir)
    export_zones(zones, output_dir=zones_dir)

    if enable_export_configs:
        export_configs(zones, config, output_dir=zones_dir, only_root=True)

