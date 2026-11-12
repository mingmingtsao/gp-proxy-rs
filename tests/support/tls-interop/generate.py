#!/usr/bin/env python3
"""Generate PUBLIC SYNTHETIC TLS test credentials; never use these keys elsewhere."""
import argparse
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--openssl', required=True, type=Path, help='OpenSSL >=3.5 executable')
parser.add_argument('--new-keys', action='store_true', help='explicitly replace public synthetic keys')
args = parser.parse_args()
binary = args.openssl.resolve(strict=True)
root = Path(__file__).resolve().parent
env = {'PATH': '/usr/bin:/bin', 'OPENSSL_CONF': os.devnull, 'LANG': 'C'}

def run(*command):
    result = subprocess.run([str(binary), *map(str, command)], cwd=root, env=env,
                            capture_output=True, timeout=30, check=False)
    if result.returncode:
        raise SystemExit('synthetic fixture generation failed; command: ' + command[0])

for name, algorithm in [
    ('ca-rsa', ['RSA', '-pkeyopt', 'rsa_keygen_bits:2048']),
    ('rsa', ['RSA', '-pkeyopt', 'rsa_keygen_bits:2048']),
    ('ca-ecdsa', ['EC', '-pkeyopt', 'ec_paramgen_curve:P-256']),
    ('ecdsa', ['EC', '-pkeyopt', 'ec_paramgen_curve:P-384']),
]:
    key = root / (name + '-key.pem')
    if args.new_keys:
        run('genpkey', '-algorithm', *algorithm, '-out', key)
        key.chmod(0o644)  # Deliberately public, committed synthetic test keys.
    elif not key.is_file() or key.is_symlink():
        raise SystemExit('missing synthetic key; initial generation requires --new-keys')

for index, name in enumerate(['ca-rsa', 'ca-ecdsa'], 1):
    run('req', '-new', '-x509', '-key', root / (name + '-key.pem'), '-sha256',
        '-subj', '/CN=gp-proxy PUBLIC SYNTHETIC ' + name,
        '-set_serial', str(index), '-not_before', '20200101000000Z',
        '-not_after', '21200101000000Z', '-out', root / (name + '-cert.pem'),
        '-addext', 'basicConstraints=critical,CA:true,pathlen:0',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
        '-addext', 'subjectKeyIdentifier=hash')

for name, key, ca, serial, start, end, purpose in [
    ('rsa', 'rsa', 'ca-rsa', 11, '20200101000000Z', '21200101000000Z', 'serverAuth'),
    ('ecdsa', 'ecdsa', 'ca-ecdsa', 12, '20200101000000Z', '21200101000000Z', 'serverAuth'),
    ('expired', 'ecdsa', 'ca-ecdsa', 13, '20190101000000Z', '20200101000000Z', 'serverAuth'),
    ('wrong-eku', 'ecdsa', 'ca-ecdsa', 14, '20200101000000Z', '21200101000000Z', 'clientAuth'),
]:
    run('req', '-new', '-x509', '-key', root / (key + '-key.pem'), '-sha256',
        '-CA', root / (ca + '-cert.pem'), '-CAkey', root / (ca + '-key.pem'),
        '-subj', '/CN=PUBLIC SYNTHETIC localhost', '-set_serial', str(serial),
        '-not_before', start, '-not_after', end, '-out', root / (name + '-cert.pem'),
        '-addext', 'basicConstraints=critical,CA:false',
        '-addext', 'keyUsage=critical,digitalSignature',
        '-addext', 'extendedKeyUsage=' + purpose,
        '-addext', 'subjectAltName=DNS:localhost',
        '-addext', 'subjectKeyIdentifier=hash', '-addext', 'authorityKeyIdentifier=keyid')
print('Generated ten PUBLIC SYNTHETIC PEM fixtures with fixed validity periods.')
