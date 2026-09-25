"""Smoke test against an actual release binary; only temporary key generation.
Called separately by CI, does not start a VPN or print generated keys.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from provision import parse_x25519
from vpnctl import run


def main():
    binary = Path(sys.argv[1]).resolve()
    result = run([binary, 'x25519'])
    private, public = parse_x25519(result.stdout, result.stderr)
    # Re-derive the same pair in Xray, checking that Hash32 was not selected.
    derived = run([binary, 'x25519', '-i', private])
    if parse_x25519(derived.stdout, derived.stderr) != (private, public):
        raise RuntimeError('Xray key derivation did not round-trip')
    print('OK: real Xray x25519 generation and derivation, keys not logged')


if __name__ == '__main__':
    main()
