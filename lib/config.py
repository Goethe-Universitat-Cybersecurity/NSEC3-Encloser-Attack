import json


DEFAULT = {
        'nsec3': {
            'iterations': 0,
            'salt': '',
            'algorithm': 1,
            'tight': False
            },
        'ns': '127.0.0.1',
        'path_prefix': '',
        'ttl': 0
}


# https://stackoverflow.com/questions/70310388/how-to-merge-nested-dictionaries/70310511#70310511
def combine_into(d: dict, combined: dict) -> None:
    """
    Does not overwrite combined
    """
    for k, v in d.items():
        if isinstance(v, dict):
            combine_into(v, combined.setdefault(k, {}))
        elif k not in combined: # added check
            combined[k] = v



def init_zones(zones, default=None):
    if default is None:
        default = DEFAULT
    else:
        combine_into(DEFAULT, default)

    for zone in zones:
        origin = zone['origin']
        if origin[0] == '.': # remove leading '.'
            origin = origin[1:]

        # TODO automize this better
        # nsec3
        if 'nsec3' not in zone:
            zone['nsec3'] = default['nsec3']
        if 'iterations' not in zone['nsec3']:
            zone['nsec3']['iterations'] = default['nsec3']['iterations']
        if 'salt' not in zone['nsec3']:
            zone['nsec3']['salt'] = default['nsec3']['salt']
        if 'algorithm' not in zone['nsec3']:
            zone['nsec3']['algorithm'] = default['nsec3']['algorithm']
        if 'tight' not in zone['nsec3']:
            zone['nsec3']['tight'] = default['nsec3']['tight']

        # ns
        if 'ns' not in zone:
            if default and 'ns' in default:
                # TODO expand on origin
                zone['ns'] = default['ns']
            else:
                zone['ns'] = '127.0.0.1'
        if type(zone['ns']) == str:
            zone['ns'] = [{'ns': 'ns1.'+origin, 'ip': zone['ns']}]

        # soa
        if 'soa' not in zone:
            ns = zone['ns'][0]['ns']
            zone['soa'] = f'{ns} {ns} 0 0 0 10 10'

        # ttl
        if 'ttl' not in zone:
            zone['ttl'] = default['ttl']

        # rrsets
        if 'rrsets' not in zone:
            zone['rrsets'] = []
        if type(zone['rrsets']) == str:
            zone['rrsets'] = list(zone['rrsets'].strip().split())



def init_defaults(config):
    default = config['default'] if 'default' in config else None
    
    if 'zones' in config:
        init_zones(config['zones'], default=default)


def load_config(filename):
    with open(filename) as f:
        config = json.load(f)
        init_defaults(config)
        return config

