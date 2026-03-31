#!/usr/bin/env python3
"""
log_generator.py
SSH Brute Force Attack Log Simulator
Author: Vijay Srinivasan
Description: Simulates SSH brute force attack log entries for Splunk ingestion.
             Generates realistic auth.log entries without needing a live target.
MITRE ATT&CK: T1110 - Brute Force

Usage:
    python3 log_generator.py --target 192.168.20.20 --count 50
    python3 log_generator.py --target 192.168.20.20 --count 100 --output /var/log/auth.log
"""

import argparse
import random
import time
import sys
from datetime import datetime, timezone

# ── Common usernames attackers try ────────────────────────────────────────────
COMMON_USERNAMES = [
    'root', 'admin', 'user', 'ubuntu', 'fakeuser', 'test', 'guest',
    'administrator', 'pi', 'oracle', 'postgres', 'mysql', 'apache',
    'nginx', 'deploy', 'git', 'jenkins', 'ansible', 'vagrant'
]

# ── Common attacker ports ──────────────────────────────────────────────────────
def random_port():
    return random.randint(32768, 65535)

# ── Generate a single failed login log line ────────────────────────────────────
def generate_failed_login(attacker_ip: str, username: str, hostname: str = 'ubuntu') -> str:
    pid = random.randint(1000, 9999)
    port = random_port()
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')
    return (
        f"{timestamp} {hostname} sshd[{pid}]: "
        f"Failed password for invalid user {username} "
        f"from {attacker_ip} port {port} ssh2"
    )

# ── Generate a connection closed line ─────────────────────────────────────────
def generate_connection_closed(attacker_ip: str, hostname: str = 'ubuntu') -> str:
    pid = random.randint(1000, 9999)
    port = random_port()
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')
    return (
        f"{timestamp} {hostname} sshd[{pid}]: "
        f"Connection closed by invalid user from "
        f"{attacker_ip} port {port} [preauth]"
    )

# ── Generate a Received disconnect line ───────────────────────────────────────
def generate_disconnect(attacker_ip: str, hostname: str = 'ubuntu') -> str:
    pid = random.randint(1000, 9999)
    port = random_port()
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')
    return (
        f"{timestamp} {hostname} sshd[{pid}]: "
        f"Received disconnect from {attacker_ip} port {port}:11: "
        f"Bye Bye [preauth]"
    )

# ── Main generator ─────────────────────────────────────────────────────────────
def generate_attack_logs(
    attacker_ip: str,
    count: int,
    username: str = None,
    hostname: str = 'ubuntu',
    output_file: str = None,
    delay: float = 0.1
):
    print(f"\n[*] SSH Brute Force Log Generator")
    print(f"[*] Attacker IP  : {attacker_ip}")
    print(f"[*] Target host  : {hostname}")
    print(f"[*] Login attempts: {count}")
    print(f"[*] Output       : {output_file or 'stdout'}")
    print(f"[*] MITRE ATT&CK : T1110 - Brute Force\n")

    lines = []

    for i in range(count):
        # Pick username — fixed or random from list
        user = username or random.choice(COMMON_USERNAMES)

        # Generate failed login
        log_line = generate_failed_login(attacker_ip, user, hostname)
        lines.append(log_line)

        # Occasionally add a disconnect line (realistic pattern)
        if random.random() < 0.3:
            lines.append(generate_connection_closed(attacker_ip, hostname))
        if random.random() < 0.2:
            lines.append(generate_disconnect(attacker_ip, hostname))

        if delay > 0:
            time.sleep(delay)

        # Progress indicator
        if (i + 1) % 10 == 0:
            print(f"[+] Generated {i + 1}/{count} attack entries...")

    print(f"\n[✓] Generated {len(lines)} total log lines.")

    # Output
    if output_file:
        try:
            with open(output_file, 'a') as f:
                for line in lines:
                    f.write(line + '\n')
            print(f"[✓] Written to {output_file}")
            print(f"[*] Splunk should pick these up within 30 seconds.")
        except PermissionError:
            print(f"[!] Permission denied: {output_file}")
            print(f"    Try: sudo python3 log_generator.py ...")
            sys.exit(1)
    else:
        for line in lines:
            print(line)

    print(f"\n[*] Verify in Splunk:")
    print(f'    index=main "Failed password" | stats count by src_ip')

# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='SSH Brute Force Log Generator for Splunk SIEM Lab',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Print to stdout
  python3 log_generator.py --target 192.168.20.20 --count 50

  # Write to auth.log (requires sudo)
  sudo python3 log_generator.py --target 192.168.20.20 --count 100 --output /var/log/auth.log

  # Use specific username
  python3 log_generator.py --target 192.168.20.20 --count 30 --username admin

  # Fast generation (no delay)
  python3 log_generator.py --target 192.168.20.20 --count 200 --delay 0
        """
    )
    parser.add_argument('--target',   required=True,
                        help='Target/victim IP address (e.g. 192.168.20.20)')
    parser.add_argument('--count',    type=int, default=50,
                        help='Number of failed login attempts to generate (default: 50)')
    parser.add_argument('--username', default=None,
                        help='Specific username to target (default: random from list)')
    parser.add_argument('--hostname', default='ubuntu',
                        help='Hostname to appear in logs (default: ubuntu)')
    parser.add_argument('--output',   default=None,
                        help='Output file path (default: stdout). Use /var/log/auth.log for Splunk')
    parser.add_argument('--delay',    type=float, default=0.05,
                        help='Delay between entries in seconds (default: 0.05)')
    args = parser.parse_args()

    generate_attack_logs(
        attacker_ip=args.target,
        count=args.count,
        username=args.username,
        hostname=args.hostname,
        output_file=args.output,
        delay=args.delay
    )

if __name__ == '__main__':
    main()
