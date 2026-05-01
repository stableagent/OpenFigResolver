#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OpenFigResolver – Advanced DNS Resolver Tester with Multi‑Stage Validation
"""

import socket
import struct
import random
import sys
import threading
import time
import queue
import argparse
import os
from datetime import datetime

# ======================================================================
#  DEFAULT CONFIGURATION (can be overridden by command line)
# ======================================================================

RESOLVER_FILE = "resolvers.txt"
MAX_WORKERS = 50
QUERY_TIMEOUT = 3.0
RETRY_DELAY = 0.5
DNS_PORT = 53
MAX_RESPONSE_SIZE = 512
OUTPUT_DIR = "results"
OUTPUT_FORMAT = "simple"
MIKROTIK_EXPORT = False

# Multi‑stage validation (disabled by default)
FIRST_DOMAIN = None
FIRST_RETRIES = 3
SECOND_DOMAIN = None
SECOND_RETRIES = 5
BLOCKED_IP = None
OUTPUT_OK_FILE = None

# ======================================================================
#  DNS helpers (unchanged)
# ======================================================================

def build_dns_query(domain_name, query_id=None):
    if query_id is None:
        query_id = random.randint(0, 65535)
    flags = 0x0100
    header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
    qname = b""
    for part in domain_name.encode("ascii").split(b"."):
        qname += bytes([len(part)]) + part
    qname += b"\x00"
    qtype = 1
    qclass = 1
    question = qname + struct.pack("!HH", qtype, qclass)
    return header + question

def parse_dns_response(packet):
    try:
        ident, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
        rcode = flags & 0x000F
        if rcode != 0 or ancount == 0:
            return rcode, None
        offset = 12
        while packet[offset] != 0:
            offset += packet[offset] + 1
        offset += 1
        offset += 4
        for _ in range(ancount):
            if (packet[offset] & 0xC0) == 0xC0:
                offset += 2
            else:
                while packet[offset] != 0:
                    offset += packet[offset] + 1
                offset += 1
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset+10])
            offset += 10
            if rtype == 1:
                ip_bytes = packet[offset:offset+rdlength]
                ip_address = socket.inet_ntoa(ip_bytes)
                return rcode, ip_address
            else:
                offset += rdlength
        return rcode, None
    except (struct.error, IndexError):
        return -1, None

def query_resolver(resolver_ip, domain, timeout, retries, retry_delay, dns_port):
    query_data = build_dns_query(domain)
    for attempt in range(retries):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start_time = time.time()
        try:
            sock.sendto(query_data, (resolver_ip, dns_port))
            response, _ = sock.recvfrom(MAX_RESPONSE_SIZE)
            elapsed = time.time() - start_time
            rcode, ip = parse_dns_response(response)
            if rcode == 0 and ip is not None:
                return True, ip, elapsed, ""
            elif rcode == 0 and ip is None:
                return False, None, elapsed, "no A record found"
            else:
                return False, None, elapsed, f"DNS error code {rcode}"
        except socket.timeout:
            elapsed = time.time() - start_time
            if attempt + 1 == retries:
                return False, None, elapsed, "timeout"
            time.sleep(retry_delay)
        except Exception as e:
            return False, None, -1, str(e)
        finally:
            sock.close()
    return False, None, -1, "unexpected error"

# ======================================================================
#  Multi‑stage validation logic (NEW)
# ======================================================================

def validate_resolver(resolver_ip, first_domain, first_retries, second_domain, second_retries, blocked_ip, timeout, retry_delay, dns_port):
    """
    Returns (overall_success, first_ip, second_ip, first_elapsed, second_elapsed, error_msg)
    """
    # Stage 1: first domain
    ok1, ip1, t1, err1 = query_resolver(resolver_ip, first_domain, timeout, first_retries, retry_delay, dns_port)
    if not ok1:
        return False, None, None, t1, None, f"First domain failed: {err1}"

    # Stage 2: second domain
    ok2, ip2, t2, err2 = query_resolver(resolver_ip, second_domain, timeout, second_retries, retry_delay, dns_port)
    if not ok2:
        return False, ip1, None, t1, t2, f"Second domain failed: {err2}"

    # Check blocked IP
    if blocked_ip and ip2 == blocked_ip:
        return False, ip1, ip2, t1, t2, f"Second domain returned blocked IP {blocked_ip}"

    return True, ip1, ip2, t1, t2, ""

def test_resolvers_multistage(resolvers, args):
    """Run the multi‑stage validation on all resolvers and collect results."""
    results = []  # list of (resolver, success, ip1, ip2, t1, t2, error)
    for idx, resolver in enumerate(resolvers, 1):
        print(f"[{idx}/{len(resolvers)}] Testing {resolver} ...", flush=True)
        success, ip1, ip2, t1, t2, err = validate_resolver(
            resolver,
            args.first_domain, args.first_retries,
            args.second_domain, args.second_retries,
            args.blocked_ip,
            args.timeout, args.retry_delay, args.dns_port
        )
        results.append((resolver, success, ip1, ip2, t1, t2, err))
        # Real‑time feedback
        if success:
            print(f"  -> PASS: google -> {ip1} ({t1:.3f}s), bbc -> {ip2} ({t2:.3f}s)", flush=True)
        else:
            print(f"  -> FAIL: {err}", flush=True)
    return results

# ======================================================================
#  Output functions
# ======================================================================

def write_ok_file(results, ok_filename, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    ok_path = os.path.join(output_dir, ok_filename)
    passed = [r[0] for r in results if r[1] is True]
    with open(ok_path, 'w', encoding='utf-8') as f:
        f.write(f"# OpenFigResolver – OK resolvers after multi‑stage validation\n")
        f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for ip in passed:
            f.write(f"{ip}\n")
    print(f"\n[FILE] OK resolvers saved to: {ok_path}", flush=True)
    return passed

def write_mikrotik_script(passed_resolvers, output_dir, base_filename):
    if not passed_resolvers:
        print("[WARN] No passed resolvers, MikroTik script not generated.", flush=True)
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    mikrotik_file = os.path.join(output_dir, f"{base_filename}_{timestamp}_mikrotik.rsc")
    with open(mikrotik_file, 'w', encoding='utf-8') as f:
        f.write("# MikroTik RouterOS script – add all validated DNS resolvers\n")
        f.write(f"# Generated by OpenFigResolver on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("/ip firewall address-list\n")
        for res in passed_resolvers:
            f.write(f'add list="working-dns" address={res} comment="Validated resolver"\n')
        f.write("\n# To apply: /import file-name=....rsc\n")
    print(f"[FILE] MikroTik script saved to: {mikrotik_file}", flush=True)

def write_detailed_report(results, output_dir, args):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(output_dir, f"multistage_report_{timestamp}.txt")
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"OpenFigResolver Multi‑Stage Report\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"First domain : {args.first_domain} (max retries {args.first_retries})\n")
        f.write(f"Second domain: {args.second_domain} (max retries {args.second_retries})\n")
        if args.blocked_ip:
            f.write(f"Blocked IP   : {args.blocked_ip}\n")
        f.write("\nDetailed results:\n")
        f.write("-" * 80 + "\n")
        for resolver, success, ip1, ip2, t1, t2, err in results:
            if success:
                f.write(f"{resolver} : PASS (google -> {ip1}, {t1:.3f}s ; bbc -> {ip2}, {t2:.3f}s)\n")
            else:
                f.write(f"{resolver} : FAIL – {err}\n")
    print(f"[FILE] Detailed report saved to: {report_file}", flush=True)

# ======================================================================
#  Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="Multi‑stage DNS resolver validator")
    # Standard options
    parser.add_argument("--resolvers", "-r", default=RESOLVER_FILE, help="File with resolver IPs")
    parser.add_argument("--workers", "-w", type=int, default=MAX_WORKERS, help="Not used in multistage mode (sequential)")
    parser.add_argument("--timeout", "-t", type=float, default=QUERY_TIMEOUT, help="Query timeout per attempt")
    parser.add_argument("--retry-delay", type=float, default=RETRY_DELAY, help="Delay between retries")
    parser.add_argument("--dns-port", type=int, default=DNS_PORT, help="DNS port")
    parser.add_argument("--output-dir", "-o", default=OUTPUT_DIR, help="Output folder")
    parser.add_argument("--mikrotik", action="store_true", help="Generate MikroTik script for passed resolvers")

    # Multi‑stage arguments
    parser.add_argument("--first-domain", required=True, help="First domain to test (e.g., google.com)")
    parser.add_argument("--first-retries", type=int, default=3, help="Max attempts for first domain")
    parser.add_argument("--second-domain", required=True, help="Second domain to test (e.g., bbcpersian.com)")
    parser.add_argument("--second-retries", type=int, default=5, help="Max attempts for second domain")
    parser.add_argument("--blocked-ip", help="If second domain returns this IP, resolver is rejected")
    parser.add_argument("--output-ok", default="ok.txt", help="File to store IPs that passed all stages")

    args = parser.parse_args()

    # Read resolvers
    try:
        with open(args.resolvers, 'r') as f:
            resolvers = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        sys.exit(f"Error: resolver file '{args.resolvers}' not found.")
    if not resolvers:
        sys.exit("No resolvers found.")

    print("=" * 80)
    print("OpenFigResolver – Multi‑Stage DNS Validator")
    print("=" * 80)
    print(f"Resolver file      : {args.resolvers} ({len(resolvers)} IPs)")
    print(f"First domain       : {args.first_domain} (max attempts {args.first_retries})")
    print(f"Second domain      : {args.second_domain} (max attempts {args.second_retries})")
    if args.blocked_ip:
        print(f"Blocked IP (reject) : {args.blocked_ip}")
    print(f"Output directory   : {args.output_dir}")
    print(f"MikroTik export    : {args.mikrotik}")
    print("=" * 80)

    # Run multi‑stage validation (sequential, but you can parallelize later)
    results = test_resolvers_multistage(resolvers, args)

    # Write outputs
    os.makedirs(args.output_dir, exist_ok=True)
    passed_ips = write_ok_file(results, args.output_ok, args.output_dir)
    write_detailed_report(results, args.output_dir, args)
    if args.mikrotik:
        write_mikrotik_script(passed_ips, args.output_dir, "validated_dns")

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total resolvers tested : {len(resolvers)}")
    print(f"Passed all stages      : {len(passed_ips)}")
    if passed_ips:
        print("Passed IPs:")
        for ip in passed_ips:
            print(f"  {ip}")
    print(f"\nOK list saved to: {os.path.join(args.output_dir, args.output_ok)}")
    print("All done.")

if __name__ == "__main__":
    main()
