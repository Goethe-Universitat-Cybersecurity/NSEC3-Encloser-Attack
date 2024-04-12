import base64
import hashlib


# TODO length checks
# TODO check for ".."
def canonicalize(domain):
    if type(domain) is str:
        domain = domain.encode()
    domain = domain.lower()
    segments = domain.split(b'.')
    if len(segments) == 0:
        raise "No domain name provided"
    c = b''
    for segment in segments:
        if len(segment) == 0:
            break
        c += len(segment).to_bytes(1, "big")
        c += segment
    c += b'\x00'
    return c


# recursive
# def IH_sha1(salt, x, k):
#     m = hashlib.sha1()
#     if k > 0:
#         m.update(IH_sha1(salt, x, k-1) + salt)
#     else:
#         m.update(x + salt)
#     d = m.digest()
#     return d


def decode_salt(salt):
    if type(salt) is str:
        salt = bytes.fromhex(salt)
    return salt


def IH_sha1(salt, x, k):
    m = hashlib.sha1()
    m.update(x + salt)
    d = m.digest()
    for i in range(0, k):
        m = hashlib.sha1()
        m.update(d + salt)
        d = m.digest()
    return d


def H_sha1(salt, x, k):
    salt = decode_salt(salt)
    x = canonicalize(x)
    return IH_sha1(salt, x, k)


_b32_trans = b'.' * 50 + b'qrstuv' + b'.' * 9 + b'0123456789abcdefghijklmnop' + b'.' * 165


# TODO padding
def b32encode(x):
    encoded = base64.b32encode(x)
    return encoded.translate(_b32_trans)
b32 = b32encode


_b32_rev_trans = b'.' * 48 + b'ABCDEFGHIJ' + b'.' * 39 + b'KLMNOPQRSTUVWXYZ234567' + b'.' * 137


# TODO padding
def b32decode(x):
    translated = x.translate(_b32_rev_trans)
    return base64.b32decode(translated)


# TODO hacky
def hash_add(x: bytes, y: int):
    size = len(x)
    base = 2 ** (8 * size)
    x = int.from_bytes(x, 'big')
    z = (x + y) % base
    return z.to_bytes(size, 'big')


#h = H_sha1("aabbccdd", b"a.example", 12)
#print(b32(h))


