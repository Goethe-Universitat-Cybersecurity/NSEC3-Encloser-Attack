#!/usr/bin/env python
import argparse
import lib.config
import lib.keys
import os


def gen_keys(zones, keys_dir, force=False):
    if not os.path.isdir(keys_dir):
        os.makedirs(keys_dir)

    for zone in zones:
        name = zone['name']
        size = zone['keysize']

        filenames = [
            name + '.zsk.pem',
            name + '.ksk.pem',
        ]

        for filename in filenames:
            key_file = os.path.join(keys_dir, filename)
            exists = os.path.isfile(key_file)
            if exists:
                if force:
                    print(f'File exists, overwriting {filename}')
                    exists = False
                else:
                    print(f'File exists, skipping {filename}')
            else:
                print(f'Writing {filename}')
            if not exists:
                lib.keys.save_key_to_file(lib.keys.gen_key(size), key_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            description = 'Generates the Keys for the NSEC3 attack based on a configuration',
            )
    parser.add_argument('config', nargs='?', default='config.json', help='config file')
    parser.add_argument('-f', action='store_true', help='force regeneration and overwrite existing keys')
    parser.add_argument('-o', '--output', default='keys', help='output directory to which keys are written to')
    args = parser.parse_args()
    config_file = args.config
    force = args.f
    keys_dir = args.output
    print(f'Creating keys from {config_file}')

    config = lib.config.load_config(config_file)
    if 'zones' not in config:
        print('Error: No zones found in config, exiting.')
        exit(-1) 

    gen_keys(config['zones'], keys_dir, force=force)
