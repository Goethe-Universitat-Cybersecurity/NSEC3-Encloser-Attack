import dns.zone
import dns.rdtypes.ANY.NSEC3 as NSEC3
from dns.dnssec import *

from lib.nsec3 import *

from typing import Callable, Dict, List, Optional, Set, Tuple, Union, cast


# Fixes to dns.dnssec to support NSEC3


def sign_zone(
    zone: dns.zone.Zone,
    txn: Optional[dns.transaction.Transaction] = None,
    keys: Optional[List[Tuple[PrivateKey, DNSKEY]]] = None,
    add_dnskey: bool = True,
    dnskey_ttl: Optional[int] = None,
    inception: Optional[Union[datetime, str, int, float]] = None,
    expiration: Optional[Union[datetime, str, int, float]] = None,
    lifetime: Optional[int] = None,
    nsec3: Optional[NSEC3PARAM] = None,
    nsec3_tight: bool = False,
    rrset_signer: Optional[RRsetSigner] = None,
    policy: Optional[Policy] = None,
) -> None:
    """Sign zone.

    *zone*, a ``dns.zone.Zone``, the zone to sign.

    *txn*, a ``dns.transaction.Transaction``, an optional transaction to use for
    signing.

    *keys*, a list of (``PrivateKey``, ``DNSKEY``) tuples, to use for signing. KSK/ZSK
    roles are assigned automatically if the SEP flag is used, otherwise all RRsets are
    signed by all keys.

    *add_dnskey*, a ``bool``.  If ``True``, the default, all specified DNSKEYs are
    automatically added to the zone on signing.

    *dnskey_ttl*, a``int``, specifies the TTL for DNSKEY RRs. If not specified the TTL
    of the existing DNSKEY RRset used or the TTL of the SOA RRset.

    *inception*, a ``datetime``, ``str``, ``int``, ``float`` or ``None``, the signature
    inception time.  If ``None``, the current time is used.  If a ``str``, the format is
    "YYYYMMDDHHMMSS" or alternatively the number of seconds since the UNIX epoch in text
    form; this is the same the RRSIG rdata's text form. Values of type `int` or `float`
    are interpreted as seconds since the UNIX epoch.

    *expiration*, a ``datetime``, ``str``, ``int``, ``float`` or ``None``, the signature
    expiration time.  If ``None``, the expiration time will be the inception time plus
    the value of the *lifetime* parameter.  See the description of *inception* above for
    how the various parameter types are interpreted.

    *lifetime*, an ``int`` or ``None``, the signature lifetime in seconds.  This
    parameter is only meaningful if *expiration* is ``None``.

    *nsec3*, a ``NSEC3PARAM`` Rdata, configures signing using NSEC3. Not yet
    implemented.

    *rrset_signer*, a ``Callable``, an optional function for signing RRsets. The
    function requires two arguments: transaction and RRset. If the not specified,
    ``dns.dnssec.default_rrset_signer`` will be used.

    Returns ``None``.
    """

    ksks = []
    zsks = []

    # if we have both KSKs and ZSKs, split by SEP flag. if not, sign all
    # records with all keys
    if keys:
        for key in keys:
            if key[1].flags & Flag.SEP:
                ksks.append(key)
            else:
                zsks.append(key)
        if not ksks:
            ksks = keys
        if not zsks:
            zsks = keys
    else:
        keys = []

    if txn:
        cm: contextlib.AbstractContextManager = contextlib.nullcontext(txn)
    else:
        cm = zone.writer()

    with cm as _txn:
        if add_dnskey:
            if dnskey_ttl is None:
                dnskey = _txn.get(zone.origin, dns.rdatatype.DNSKEY)
                if dnskey:
                    dnskey_ttl = dnskey.ttl
                else:
                    soa = _txn.get(zone.origin, dns.rdatatype.SOA)
                    dnskey_ttl = soa.ttl
            for _, dnskey in keys:
                _txn.add(zone.origin, dnskey_ttl, dnskey)

        if nsec3:
            _rrset_signer = rrset_signer or functools.partial(
                default_rrset_signer,
                signer=zone.origin,
                ksks=ksks,
                zsks=zsks,
                inception=inception,
                expiration=expiration,
                lifetime=lifetime,
                policy=policy,
                origin=zone.origin,
            )
            return sign_zone_nsec3(zone, _txn, nsec3, _rrset_signer, tight=nsec3_tight)
        else:
            _rrset_signer = rrset_signer or functools.partial(
                default_rrset_signer,
                signer=zone.origin,
                ksks=ksks,
                zsks=zsks,
                inception=inception,
                expiration=expiration,
                lifetime=lifetime,
                policy=policy,
                origin=zone.origin,
            )
            return dns.dnssec._sign_zone_nsec(zone, _txn, _rrset_signer)


def sign_zone_nsec3(
    zone: dns.zone.Zone,
    txn: dns.transaction.Transaction,
    nsec3: NSEC3PARAM,
    rrset_signer: Optional[RRsetSigner] = None,
    tight: bool = False,
) -> None:
    """NSEC3 zone signer"""

    def _txn_add_nsec3(
        txn: dns.transaction.Transaction,
        name: Optional[dns.name.Name],
        name_hash: dns.name.Name,
        next_secure_hash: Optional[dns.name.Name],
        rdclass: dns.rdataclass.RdataClass,
        ttl: int,
        rrset_signer: Optional[RRsetSigner] = None,
    ) -> None:
        """NSEC3 zone signer helper"""
        # First check if name is in zone
        types = None
        if name:
            # Name is in zone, thus obtain the bitmap from zone
            mandatory_types = set(
                [dns.rdatatype.RdataType.RRSIG]
            )
            node = txn.get_node(name)
            if node and next_secure_hash:
                types = (
                    set([rdataset.rdtype for rdataset in node.rdatasets]) | mandatory_types
                )
        else:
            # Special case for forged NSEC3 which do not belong to any name
            types = (
                set() # TODO
            )

        if not types is None:
            windows = NSEC3.Bitmap.from_rdtypes(list(types))
            rrset = dns.rrset.from_rdata(
                name_hash,
                ttl,
                NSEC3.NSEC3(
                    rdclass=rdclass,
                    rdtype=dns.rdatatype.RdataType.NSEC3,
                    algorithm=nsec3.algorithm,
                    flags=1,
                    iterations=nsec3.iterations,
                    salt=nsec3.salt,
                    next=next_secure_hash,
                    windows=windows,
                ),
            )
            txn.add(rrset)
            if rrset_signer:
                rrset_signer(txn, rrset)

    rrsig_ttl = zone.get_soa().minimum
    delegation = None

    hashes = []

    # add NSEC3PARAM
    rrset = dns.rrset.from_rdata(
        zone.origin,
        rrsig_ttl,
        nsec3
    )
    txn.add(rrset)

    for name in sorted(txn.iterate_names()):
        if delegation and name.is_subdomain(delegation):
            # names below delegations are not secure
            continue
        elif txn.get(name, dns.rdatatype.NS) and name != zone.origin:
            # inside delegation
            delegation = name
        else:
            # outside delegation
            delegation = None

        if rrset_signer:
            node = txn.get_node(name)
            if node:
                for rdataset in node.rdatasets:
                    if rdataset.rdtype == dns.rdatatype.RRSIG:
                        # do not sign RRSIGs
                        continue
                    elif delegation and rdataset.rdtype != dns.rdatatype.DS:
                        # do not sign delegations except DS records
                        continue
                    else:
                        rrset = dns.rrset.from_rdata(name, rdataset.ttl, *rdataset)
                        rrset_signer(txn, rrset)

        # We need "is not None" as the empty name is False because its length is 0.
        # TODO hash algorithm
        h = H_sha1(nsec3.salt, name.to_text(), nsec3.iterations)
        # print(h)
        # print(b32(h))
        hashes.append((b32(h), h, name))
        #if last_secure is not None:
        #    _txn_add_nsec3(txn, last_secure, name, zone.rdclass, rrsig_ttl, rrset_signer)
        #last_secure = name

    # Add forged nsec3 records around 'origin' and '*.origin' to hashes
    if tight:
        offset = 1 # TODO
        # add hash after origin
        name = zone.origin.to_text()
        h_origin = H_sha1(nsec3.salt, name, nsec3.iterations)
        h_after = hash_add(h_origin, offset)
        hashes.append((b32(h_after), h_after, None))
        # add hash before and after wildcard
        name = dns.name.Name(['*']).concatenate(zone.origin).to_text()
        h_origin = H_sha1(nsec3.salt, name, nsec3.iterations)
        h_before = hash_add(h_origin, -offset)
        hashes.append((b32(h_before), h_before, None))
        h_after = hash_add(h_origin, offset)
        hashes.append((b32(h_after), h_after, None))

    # process hashes and link to NSEC3 chain
    hashes.sort()
    last_b32h, last_h, last_name = hashes[-1]
    for b32h, h, name in hashes:
        last_hash_name = dns.name.Name([last_b32h]).concatenate(zone.origin)
        _txn_add_nsec3(
            txn, last_name, last_hash_name, h, zone.rdclass, rrsig_ttl, rrset_signer
        )
        last_b32h, last_h, last_name = b32h, h, name

