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

## Reproducing the Attack

To reproduce the NSEC3 attack, this section illustrates a possible custom setup consisting of a DNS nameserver and victim resolver.
Before continuing, make sure that the system environment has a sufficiently configured firewall as to not expose public servers to the attack zonefiles.

1. Install the NSD nameserver (current version)

   Navigate to the NLNetlabs website (https://nsd.docs.nlnetlabs.nl/en/latest/installation.html) for installation instructions.

   It is recommended to deploy the nameserver either in a VM or container. As a starting point, there is a small Dockerfile in `docker/nsd`.

   Build the container with `docker build -t <tag> <path_to_dockerfile>`, for instance:
   `cd docker/nsd && docker build -t nsd .`

   Run the container with `docker run -it --name <name> nsd bash` to open a console in the container.

   Next, the nameserver needs to be configured to host the attacker zonefiles.
   This necessitates a correct configuration of the zonefiles to generate (most importantly, the IP address given in the NS records needs to match the container's IP address).
   If no network has been configured, the container's IP address can be viewed with:
   `docker container inspect <name> | grep IPAddress`

   Generate the zones with configuration output (`./gen_zones.py -c`, see above) and copy the zones output folder from the repository directory into the docker container:
   `docker cp ./zones <name>:/etc/nsd`

   In the container console, the NSD config `/etc/nsd/nsd.conf` in the container needs to be ammended with the following lines:
   ```
   verify:
       enable: no
   remote-control:
       control-enable: no
   
   include: "/etc/nsd/zones/nsd.conf"
   ```

   At last, run NSD from the container shell with the command
   `/usr/sbin/nsd -d -c /etc/nsd/nsd.conf`

   Enable logging output with the option `-V 4`.

   Now, if no issues occured, the authoritative nameserver should be running. You can verify this by running a query of one of the zones' domains from the host system using dig:
   `dig @<ip-addr-of-nsd-container> <domain>`

2. Install a resolver. In this demonstration, we show a possible approach for Unbound 1.17.1.

   An official dockerfile can be found here: https://github.com/NLnetLabs/pythonunbound

   We included a modified version of this Dockerfile in `docker/unbound` with an updated Ubuntu version and pre-configured to Unbound 1.17.1.

   Clone the repository, change to its directory and build the Unbound container:
   `docker build -t <tag> .`

   Run the container with:
   `docker run --name <name> -it <tag> bash`

   Next, Unbound needs to be configured such that it can locate the NSD authoritative nameserver.
   This is done by modifying the `unbound.conf` file in the container working directory.
   For this, make sure that the server.module-config entry is removed from the config.

   To enable DNSSEC validation, the DNSKEY records of the attacker parent zone need to be configured manually.
   This needs to be the same key that has been used for generating the signatures, for example:
   ```
   server:
       chroot: ""
       do-ip6: no
       trust-anchor: "attack.er. DNSKEY 257 3 7 AwEAAdqDN3rJYlmGP3jJs5lCZq5NYrCn pCVlV0ko17JnbfYfLCroEF4reO/Xy0MK C9AVvSRTk83MHDuzMYXogm7m/gcn3Mh0 MwB2InP8jkPw5not+TMH/Wrbs31xkT2n RIBJJ+1lPF+e2AvwWvgREcEVTRbdhIqQ iM1StWXoTVudry4V"
   ```

   Furthermore, a stub-zone has to be configured to enable the Unbound resolver to find the NSD authoritative nameserver.
   This is achieved by adding the following to the `unbound.conf` file:
   ```
   stub-zone:
       name: "attack.er."
       stub-prime: yes
       stub-addr: <ip-addr-of-nsd-container>
   ```

   Start unbound in the container with:
   `unbound -vvv` (use `-dd` to prevent daemonization)

   You should now be able to query unbound with dig and observe the response time:
   `dig @127.0.0.1 attack.er`

If you have any issues with this guide, feel free to contact us for further guidance.
