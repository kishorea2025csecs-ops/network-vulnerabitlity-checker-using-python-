
import socket
import requests
import nmap
import ipaddress
import json
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ==========================================
# NETWORK SCANNER - EDUCATIONAL PROJECT
# Authorized private IPv4 targets only
# ==========================================

COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 5432, 8080, 8443
]

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}


def validate_ip(target):
    """Allow only private or loopback IPv4 addresses."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 address.") from exc

    if not isinstance(ip, ipaddress.IPv4Address):
        raise ValueError("IPv4 targets only.")

    if not (ip.is_private or ip.is_loopback):
        raise ValueError("Target must be private or loopback.")

    if ip.is_multicast or ip.is_unspecified:
        raise ValueError("Invalid target address.")

    return str(ip)


def portscan(target, ports=None, timeout=0.6):
    """Test a bounded list of TCP ports."""
    target = validate_ip(target)
    ports = COMMON_PORTS if ports is None else list(ports)

    if not ports or len(ports) > 256:
        raise ValueError("Select between 1 and 256 ports.")

    if any(not isinstance(p, int) or not 1 <= p <= 65535
           for p in ports):
        raise ValueError("Ports must be between 1 and 65535.")

    print(f"\n[+] Scanning TCP ports on {target}")

    open_ports = []

    def test_port(port):
        try:
            with socket.create_connection(
                (target, port), timeout=timeout
            ):
                return {
                    "port": port,
                    "state": "open",
                    "service": SERVICE_NAMES.get(
                        port, "unknown"
                    )
                }
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        tasks = [executor.submit(test_port, p) for p in ports]

        for task in as_completed(tasks):
            result = task.result()
            if result:
                open_ports.append(result)
                print(
                    f"[OPEN] {result['port']} - "
                    f"{result['service']}"
                )

    open_ports.sort(key=lambda item: item["port"])
    print(f"[+] Found {len(open_ports)} open port(s)")
    return open_ports


def banner_grab(target, port, timeout=2):
    """Read a short service greeting where one is available."""
    target = validate_ip(target)

    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Invalid TCP port.")

    result = {
        "port": port,
        "service": SERVICE_NAMES.get(port, "unknown"),
        "banner": None,
        "note": "Service identification is best-effort."
    }

    try:
        with socket.create_connection(
            (target, port), timeout=timeout
        ) as sock:
            sock.settimeout(timeout)

            # Only receive a greeting. Do not send commands.
            try:
                data = sock.recv(512)
                if data:
                    result["banner"] = data.decode(
                        "utf-8", errors="replace"
                    ).strip()
            except socket.timeout:
                pass

        if result["banner"]:
            print(f"[BANNER] {port}: {result['banner']}")
        else:
            print(f"[INFO] {port}: no greeting received")

    except OSError as exc:
        result["error"] = str(exc)
        print(f"[INFO] Port {port}: {exc}")

    return result


def network_scan(network):
    """
    Discover hosts on an explicitly supplied private IPv4 subnet.
    Example: 192.168.1.0/24
    """
    try:
        subnet = ipaddress.ip_network(network, strict=False)
    except ValueError as exc:
        raise ValueError("Invalid IPv4 subnet.") from exc

    if not isinstance(subnet, ipaddress.IPv4Network):
        raise ValueError("IPv4 subnet required.")

    if not subnet.is_private or subnet.is_multicast:
        raise ValueError("Use your authorized private subnet.")

    # Limit discovery size to keep the exercise manageable.
    if subnet.num_addresses > 256:
        raise ValueError("Use a subnet with at most 256 addresses.")

    print(f"\n[+] Discovering hosts in {subnet}")

    scanner = nmap.PortScanner()

    # Host discovery only; no port or version scan here.
    scanner.scan(
        hosts=str(subnet),
        arguments="-sn -n"
    )

    hosts = []

    for host in scanner.all_hosts():
        entry = {
            "ip": host,
            "state": scanner[host].state()
        }

        try:
            entry["hostname"] = scanner[host].hostname()
        except KeyError:
            entry["hostname"] = ""

        hosts.append(entry)
        print(
            f"[HOST] {entry['ip']} - "
            f"{entry['state']} - {entry['hostname']}"
        )

    print(f"[+] Discovered {len(hosts)} responding host(s)")
    return hosts


def http_check(target, port):
    """Check common security headers on a local HTTP service."""
    target = validate_ip(target)

    if port not in (80, 443, 8080, 8443):
        raise ValueError("Use a common HTTP/HTTPS port.")

    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{target}:{port}/"

    headers_to_check = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security"
    ]

    try:
        # Do not follow redirects to another destination.
        response = requests.get(
            url,
            timeout=3,
            allow_redirects=False,
            verify=True
        )

        present = {
            name: name in response.headers
            for name in headers_to_check
        }

        result = {
            "url": url,
            "http_status": response.status_code,
            "security_headers": present,
            "missing_headers": [
                name for name, exists in present.items()
                if not exists
            ],
            "note": (
                "Missing headers require contextual review; "
                "they do not automatically prove a vulnerability."
            )
        }

        for name, exists in present.items():
            print(
                f"[HEADER] {name}: "
                f"{'present' if exists else 'missing'}"
            )

        return result

    except requests.RequestException as exc:
        return {"url": url, "error": str(exc)}


def save_report(report, filename="scan_report.json"):
    """Save scan results as timestamped JSON."""
    report["timestamp"] = datetime.now().astimezone().isoformat()

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\n[+] Report saved to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Authorized Python Network Scanner"
    )

    parser.add_argument(
        "--target",
        help="Private IPv4 target, e.g. 127.0.0.1"
    )
    parser.add_argument(
        "--network",
        help="Authorized private subnet, e.g. 192.168.1.0/24"
    )
    parser.add_argument(
        "--headers",
        action="store_true",
        help="Check HTTP security headers"
    )
    parser.add_argument(
        "--output",
        default="scan_report.json",
        help="Output JSON filename"
    )

    args = parser.parse_args()

    if not args.target and not args.network:
        parser.error("Provide --target or --network.")

    report = {
        "project": "Python Network & Security Scanner",
        "hosts": [],
        "open_ports": [],
        "banners": [],
        "http_checks": []
    }

    try:
        if args.network:
            report["hosts"] = network_scan(args.network)

        if args.target:
            target = validate_ip(args.target)
            report["target"] = target

            report["open_ports"] = portscan(target)

            for item in report["open_ports"]:
                report["banners"].append(
                    banner_grab(target, item["port"])
                )

            if args.headers:
                for item in report["open_ports"]:
                    if item["port"] in (80, 443, 8080, 8443):
                        report["http_checks"].append(
                            http_check(target, item["port"])
                        )

        save_report(report, args.output)

    except (ValueError, nmap.PortScannerError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
