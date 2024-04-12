# NSEC3-Encloser-Attack Zonefile Generation

This project generates DNS zonefiles with custom NSEC3 parameters to reproduce and evaluate the attacks in [CVE-2023-50868](https://kb.isc.org/docs/cve-2023-50868).

## Requirements
Python3 (tested on Python3.10)

Installed Python dependencies:
- cryptography 42.0.5
- dnspython    2.6.1

## Components
- `lib`: Python utils, including:
    - `keys.py`: Wrapper functions for loading/storing keys to files
    - `nsec.py`: Implementation of DNSSEC NSEC Hashes
    - `dnssec.py`: Modified/Patched dnspython functions with NSEC3 support
    - `config.py`: Config loading utils
- `keys`: PEM-files with pre-generated keys (generated with `gen_keys.py`)
- `zones`: Zonefiles (generated with `gen_zones.py`)
- `config.json`: Example configuration

## Setup

- Configure which NSEC3 zones should be created by modifying the config.json (see [Config](#config))

- Generate keys:
  `$ ./gen_keys.py`
  
  For each zone, a KSK and ZSK are generated.
  The keys are re-used when changing the configuration as long as the zone names remain unchanged in the configuration.

- Generate zonefiles:
  `$ ./gen_zones.py -c`
  
  The option `-c` enables the export of configuration files (currently only for BIND9)

Use `--help` for more options.

## Config

The config structure contains two elements:

- `default`: Default parameters for the zones (not all are supported thus far)
- `zones`: List of all zones to be exported

### Zone

A zone contains:
- `name` (required): The name used when referencing the zone and as filename during export
- `origin` (required): The canonical zone origin domain name
- `parent`: The parent zone name (not origin), to which the NS, A, DS, and NSEC3PARAM records of this zone are added to
- `keysize` (required): The RSA key size (only RSA thus far)
- `nsec3`: The NSEC3 parameters:
    - `iterations`: defaults to 0
    - `salt`: defaults to ''
    - `algorithm`: Integer value, right now, only SHA-1 (1) is supported
    - `tight`: A special boolean which controls whether NSEC3 records immediately after the origin and before and after *.origin should be added. E.g., if *.origin has an NSEC3 record `1d..ua.origin.`, then the records for `1d..u0.origin.` and `1d..ub.origin.` are added to the zonefile, too. This ensures that every NXDOMAIN proof on a subdomain of origin (e.g., `a.origin.`) requires three NSEC3 records, since the NSEC3 records covering the origin and the wildcard have a very small range to next\_hash
- `ns`: The nameserver(s) of this zone. A single value or list of:
    - `ns`: The domain name of a nameserver, defaults to `ns1.origin`
    - `ip`: The Ipv4 domain (IPv6 currently not supported), defaults to `172.0.0.1`
- `soa`: The SOA RDATA
- `rrsets`: A list of additional RRsets, given as the 5-tuple list \[domain name, ttl, class, type, rdata\] where all values (except, optionally, ttl) are given as strings
