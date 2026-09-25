# Continuing a new installation stopped at TLS

Use `bash install.sh --resume-from-tls` only after `provision.py` completed and TLS
bootstrap failed. This is NOT repair of an existing VPN and not a force reinstall.
The command verifies saved state.json against secrets.env and every generated
identity/configuration, an empty panel inbound table and no live AWG interface.
It backs up the bootstrap, skips package installation and key generation, then
continues TLS, panel API configuration, services and local health checks.
Changed/missing identities or an existing inbound stop recovery before mutation.
Never delete state, the panel database or private keys to bypass these checks.

The pinned 3x-ui installer can issue an IP certificate itself. acme.sh then
returns exit 2 for a redundant --issue request. TLS bootstrap first checks the
ECC certificate in the ACME home: matching private key, IP SAN, remaining lifetime
and trusted server chain. A valid cached certificate is installed without another
CA order. Exit 2 is never accepted on its own. No --force or self-signed fallback
is used to hide failure. The ACME exit code and a non-secret error category are
shown, while full output remains in the private /var/log/vpn-install.log.

`tests/integration_bootstrap.py` is destructive and REFUSES non-GitHub-hosted
runners. It tests real acme.sh against a local Pebble test CA (real HTTP-01),
real 3x-ui/Xray release binaries, AWG packages/kernel/systemd, bootstrap continuation,
repeat repair, a namespaced AWG client transfer and service restarts. The test CA
is trusted ONLY in that disposable runner. No user's server/password, production
Let's Encrypt request or private configuration is sent to CI. The new workflow
is evidence of whichever stages pass, not proof of ISP reachability, firewall SSH
confirmation, VPS reboot or a full production certificate-renewal cycle.
