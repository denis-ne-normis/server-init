#!/usr/bin/env python3
"""Interactive, bounded REALITY target checks before generating identities.

stdout contains only shell-quoted assignments; prompts/results go to stderr.
No target is advertised as unblockable. Checks describe the VPS -> target path.
"""
from concurrent.futures import ThreadPoolExecutor
import errno
import os
import re
import shlex
import socket
import subprocess
import sys
import time

from xray_profile import donor_name, FINGERPRINTS

DONORS = ("www.microsoft.com", "www.ibm.com", "www.nvidia.com")


def probe(host):
    host = donor_name(host)
    start = time.monotonic()
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", host + ":443", "-servername", host,
             "-tls1_3", "-alpn", "h2", "-verify_hostname", host, "-verify_return_error"],
            input="", capture_output=True, text=True, errors="replace", timeout=12)
    except (OSError, subprocess.TimeoutExpired):
        return False, 0, "TLS-проверка недоступна или таймаут 12 с"
    output = result.stdout + result.stderr
    good = (result.returncode == 0 and re.search(r"TLSv?1[._]3", output)
            and "ALPN protocol: h2" in output and "Verify return code: 0 (ok)" in output)
    if not good:
        return False, 0, "не подтверждены TLS 1.3, h2 или сертификат для SNI"
    elapsed = round((time.monotonic() - start) * 1000)
    # HTTP/1.1 HEAD is a separate redirect hint; h2 was negotiated above.
    note = "TLS 1.3 / h2 / сертификат OK"
    try:
        head = subprocess.run(["curl", "--noproxy", "*", "-sSI", "--connect-timeout", "4", "--max-time", "8",
                               "--tlsv1.3", "--tls-max", "1.3", "--http1.1", "https://" + host + "/"],
                              capture_output=True, text=True, timeout=10)
        location = re.search(r"(?im)^location:\s*(\S+)", head.stdout)
        if location:
            from urllib.parse import urlsplit
            target = urlsplit(location.group(1))
            if target.hostname and target.hostname.lower() != host:
                return False, elapsed, "редирект на другой hostname; выберите конечный SNI"
            note += "; редирект внутри сайта"
        if head.returncode:
            note += "; HTTP HEAD не проверен"
    except (OSError, subprocess.TimeoutExpired):
        note += "; HTTP HEAD не проверен"
    return True, elapsed, note


def ask(prompt, default, read=input):
    print(prompt + f" [{default}]: ", end="", file=sys.stderr, flush=True)
    try:
        value = read().strip()
    except EOFError:
        raise ValueError("ввод прерван; настройки не сохранены") from None
    return value or default


def check_port(port):
    for family, address in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((address, port))
        except OSError as error:
            if family == socket.AF_INET6 and error.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL):
                continue  # IPv6 is disabled on this host.
            raise ValueError('TCP-порт недоступен по IPv4 или IPv6; выберите свободный порт') from None


def choose(env, interactive=False, read=input, check=probe):
    host = env.get("SNI_DONOR", "auto")
    port = env.get("VLESS_PORT", "443")
    fp = env.get("REALITY_FINGERPRINT", "chrome")
    network = env.get("VLESS_TRANSPORT", "tcp")
    if interactive:
        print("\nREALITY: универсального лучшего сайта нет. Проверка идёт с VPS, не из сети клиента.\n"
              "0) Авто: проверить кандидатов и выбрать минимальное время TLS\n"
              + "\n".join(f"{i}) {name}" for i, name in enumerate(DONORS, 1))
              + "\n4) Свой hostname\n5) Сохранить SNI_DONOR из окружения: " + host, file=sys.stderr)
        default = "5" if "SNI_DONOR" in env else "0"
        while True:
            selection = ask("Маскировка", default, read)
            if selection in ("0", "1", "2", "3", "4", "5"):
                if selection == "0":
                    host = "auto"
                elif selection in ("1", "2", "3"):
                    host = DONORS[int(selection) - 1]
                elif selection == "4":
                    host = ask("Свой SNI (без https://, порта и пути)", host if host != "auto" else DONORS[0], read)
                break
            print("Выберите пункт 0–5.", file=sys.stderr)
        print("\n1) 443 — обычный HTTPS, рекомендуется\n2) 7443 — альтернативный\n3) Свой порт\n"
              "4) Сохранить VLESS_PORT из окружения: " + port + "\nНи один порт не гарантирует обход блокировок.", file=sys.stderr)
        while True:
            selection = ask("TCP-порт", "4" if "VLESS_PORT" in env else "1", read)
            if selection in ("1", "2", "3", "4"):
                port = {"1": "443", "2": "7443"}.get(selection, port)
                if selection == "3":
                    port = ask("Свой TCP-порт", port, read)
                break
            print("Выберите пункт 1–4.", file=sys.stderr)
        print("\n1) chrome — рекомендуется с актуальным Xray\n2) firefox\n3) safari", file=sys.stderr)
        while True:
            selection = ask("TLS fingerprint", str(FINGERPRINTS.index(fp) + 1) if fp in FINGERPRINTS else "1", read)
            if selection in ("1", "2", "3"):
                fp = FINGERPRINTS[int(selection) - 1]
                break
            print("Выберите пункт 1–3.", file=sys.stderr)
        print("\nПрофиль VLESS:\n1) TCP + REALITY + Vision — простой прямой профиль\n"
              "2) XHTTP + REALITY — HTTP/2, без Vision\n"
              "TLS и XHTTP не альтернативы: XHTTP — транспорт. Для XHTTP + TLS нужен отдельный домен и сертификат.", file=sys.stderr)
        while True:
            selection = ask("Профиль", "2" if network == "xhttp" else "1", read)
            if selection in ("1", "2"):
                network = {"1": "tcp", "2": "xhttp"}[selection]
                break
            print("Выберите пункт 1–2.", file=sys.stderr)
    if network not in ("tcp", "xhttp"):
        raise ValueError("VLESS_TRANSPORT: tcp или xhttp")
    if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("TCP-порт должен быть 1..65535")
    if int(port) == 80 or any(int(port) == int(env.get(key, fallback)) for key, fallback in
                            (("AGG_PORT", "2087"), ("SUB_PORT", "2096"), ("PANEL_PORT", "0"))):
        raise ValueError("VLESS-порт занят назначением ACME/панели/подписок/раздачи")
    if fp not in FINGERPRINTS:
        raise ValueError("fingerprint: chrome, firefox или safari")
    # Read-only availability check; never kill a listener to free the selected port.
    check_port(int(port))
    candidates = DONORS if host == "auto" else (donor_name(host),)
    print("\nПроверяю TLS 1.3, ALPN h2 и сертификаты кандидатов…", file=sys.stderr, flush=True)
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(check, candidates))
    valid = []
    for candidate, (ok, milliseconds, note) in zip(candidates, results):
        print(f"{'OK' if ok else 'FAIL'} {candidate}: {note} ({milliseconds} мс)", file=sys.stderr)
        if ok:
            valid.append((milliseconds, candidate))
    if not valid:
        raise ValueError("нет подходящего target; проверьте DNS/выход в интернет или укажите другой SNI_DONOR")
    host = min(valid)[1]
    print(f"Выбрано: {host}:443, VLESS {network.upper()} {int(port)}, fingerprint {fp}.\n"
          "Обновите Xray на роутере; успешный TLS-тест не доказывает обход фильтра вашего провайдера.", file=sys.stderr)
    return {"SNI_DONOR": host, "VLESS_PORT": str(int(port)), "REALITY_FINGERPRINT": fp, "VLESS_TRANSPORT": network}


if __name__ == "__main__":
    try:
        selected = choose(os.environ, interactive=sys.stdin.isatty())
        for key, value in selected.items():
            print(f"export {key}={shlex.quote(value)}")
    except (ValueError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
