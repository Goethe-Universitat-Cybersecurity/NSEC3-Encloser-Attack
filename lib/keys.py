#!/usr/bin/python3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os.path


def gen_key(size):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=size, backend=default_backend()
    )
    return private_key


def save_key_to_file(pk, filename):
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def load_key_from_file(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    return private_key


if __name__ == '__main__':
    # TODO
    keys = [
        ("root_ksk_1024", 1024),
        ("root_zsk_1024", 1024),
        ("example_ksk_1024", 1024),
        ("example_zsk_1024", 1024),
        ("example_ksk_2048", 2048),
        ("example_zsk_2048", 2048),
        ("example_ksk_4096", 4096),
        ("example_zsk_4096", 4096),
        ]
    keys_dir = "./keys"
    if not os.path.isdir(keys_dir):
        os.makedirs(keys_dir)

    for name, size in keys:
        key_file = os.path.join(keys_dir, name)
        if not os.path.isfile(key_file):
            save_key(gen_key(size), key_file)

