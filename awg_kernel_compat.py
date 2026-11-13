"""Narrow fallback for the known PPA AWG source; never patch unknown releases.

Exact upstream change (two preprocessor lines):
https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/commit/70ae2481ca4a0530b500fba976984fa5a22b89aa
Only used after a failed fresh package installation, before VPN identities exist.
"""
import hashlib
import os
from pathlib import Path
import stat
import tempfile

SOURCE_SHA256 = 'b14346040ce0188c47e2db2baad1a4f21aa784510f6c95bbb4aa58d5bbe691c9'
PATCHED_SHA256 = 'b782a60011234c9de74a7db5966a4a83234f82b0099ff568049e9a5f17a40e83'
HEADER = Path('/usr/src/amneziawg-1.0.0/compat/compat.h')
ORIGINAL = b'#define setup_udp_tunnel_sock(net, sk, sock_cfg) setup_udp_tunnel_sock(net, sk->sk_socket, sock_cfg)\n'
REPLACEMENT = (b'#if !(defined(UTS_UBUNTU_RELEASE_ABI) && LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0) && UTS_UBUNTU_RELEASE_ABI >= 38)\n'
               + ORIGINAL + b'#endif\n')


def patched_content(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest == PATCHED_SHA256:
        return data
    if digest != SOURCE_SHA256 or data.count(ORIGINAL) != 1:
        raise ValueError('Unknown AWG compatibility header; refusing to patch. Inspect DKMS make.log.')
    patched = data.replace(ORIGINAL, REPLACEMENT, 1)
    if hashlib.sha256(patched).hexdigest() != PATCHED_SHA256:
        raise ValueError('AWG upstream patch checksum mismatch')
    return patched


def main():
    if os.geteuid() != 0:
        raise SystemExit('Root required for AWG package repair')
    info = HEADER.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
        raise ValueError('Expected a regular root-owned AWG compatibility header')
    original = HEADER.read_bytes()
    patched = patched_content(original)
    if patched == original:
        print('Pinned upstream AWG compatibility fix already present')
        return
    backup = HEADER.with_name('compat.h.server-init-backup')
    if backup.exists() or backup.is_symlink():
        if backup.is_symlink() or backup.read_bytes() != original:
            raise ValueError('Unexpected AWG source backup; refusing to overwrite')
    else:
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
    fd, temporary = tempfile.mkstemp(prefix='.compat-', dir=HEADER.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(patched)
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, HEADER)
    finally:
        Path(temporary).unlink(missing_ok=True)
    print('Applied SHA256-verified upstream AWG fix 70ae248; original source backed up')


if __name__ == '__main__':
    main()
