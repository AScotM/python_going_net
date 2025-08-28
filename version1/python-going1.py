#!/usr/bin/env python3
"""
Enhanced TCP Connection Monitor
- Parses /proc/net/tcp and /proc/net/tcp6
- Shows both IPv4 and IPv6 connections
- Clean tabular output with dynamic column widths
- Supports real-time monitoring, process information, filtering, permissions handling, and colorized output
- Added JSON output, subnet filtering, sorting, and signal handling
- Uses ANSI colors for Linux compatibility, no external dependencies
"""

import argparse
import json
import logging
import os
import platform
import re
import signal
import sys
import time
import glob
from typing import List, NamedTuple
from queue import Queue
from threading import Thread
import ipaddress

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

class Socket(NamedTuple):
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    process: str  # Process name and PID

TCP_STATES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
    12: "NEW_SYN_RECV",
}

STATE_COLORS = {
    "ESTABLISHED": "\033[32m{}\033[0m",  # Green
    "LISTEN": "\033[34m{}\033[0m",       # Blue
    "CLOSE": "\033[31m{}\033[0m",        # Red
    "TIME_WAIT": "\033[33m{}\033[0m",    # Yellow
    "SYN_SENT": "\033[36m{}\033[0m",     # Cyan
    "SYN_RECV": "\033[36m{}\033[0m",     # Cyan
    "FIN_WAIT1": "\033[35m{}\033[0m",    # Magenta
    "FIN_WAIT2": "\033[35m{}\033[0m",    # Magenta
    "CLOSE_WAIT": "\033[31m{}\033[0m",   # Red
    "LAST_ACK": "\033[31m{}\033[0m",     # Red
    "CLOSING": "\033[31m{}\033[0m",      # Red
    "NEW_SYN_RECV": "\033[36m{}\033[0m", # Cyan
}

# Cache for process name lookups
PROCESS_CACHE = {}

def parse_hex_ip_port(hex_str: str) -> tuple[str, int]:
    """Parse IP:port from hex format (e.g., '0100007F:0016' or '20010DB8...:1F90')"""
    try:
        ip_part, port_part = hex_str.split(':')
        ip_bytes = bytes.fromhex(ip_part)
        
        if len(ip_bytes) == 4:
            ip = str(ipaddress.IPv4Address(ip_bytes[::-1]))
        elif len(ip_bytes) == 16:
            ip = str(ipaddress.IPv6Address(ip_bytes))
        else:
            raise ValueError(f"Invalid IP length: {len(ip_bytes)}")
        
        port = int(port_part, 16)
        return ip, port
    except ValueError as e:
        raise ValueError(f"Invalid format: {hex_str}, error: {e}")

def get_process_name(inode: str) -> str:
    """Find process name and PID by matching socket inode, using cache"""
    if inode in PROCESS_CACHE:
        return PROCESS_CACHE[inode]
    
    for pid_dir in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            if os.path.islink(pid_dir) and os.readlink(pid_dir).endswith(f"socket:[{inode}]"):
                pid = pid_dir.split("/")[2]
                with open(f"/proc/{pid}/comm", "r") as f:
                    process_name = f"{f.read().strip()} ({pid})"
                    PROCESS_CACHE[inode] = process_name
                    return process_name
        except (IOError, OSError):
            continue
    PROCESS_CACHE[inode] = "Unknown"
    return "Unknown"

def read_tcp_connections(file_path: str, verbose: bool) -> List[Socket]:
    """Read active TCP connections from the specified file"""
    sockets = []
    if not os.path.exists(file_path):
        if verbose:
            logging.info(f"File {file_path} does not exist")
        return sockets
    if not os.access(file_path, os.R_OK):
        logging.error(f"No read permission for {file_path}. Try running with sudo.")
        return sockets

    try:
        with open(file_path, 'r') as f:
            header = f.readline().strip()
            if not re.match(r'\s*sl\s+local_address\s+rem_address', header):
                logging.error(f"Invalid TCP file format: {file_path}")
                return sockets
            for line in f:
                fields = re.split(r'\s+', line.strip())
                if len(fields) < 10:
                    if verbose:
                        logging.warning(f"Skipping malformed line: {line.strip()}")
                    continue
                
                try:
                    local = parse_hex_ip_port(fields[1])
                    remote = parse_hex_ip_port(fields[2])
                    state_code = int(fields[3], 16)
                    inode = fields[9]
                    
                    state = TCP_STATES.get(state_code, f"UNKNOWN({state_code})")
                    if state.startswith("UNKNOWN") and verbose:
                        logging.warning(f"Unknown state code: {state_code}")
                    
                    process = get_process_name(inode)
                    
                    sockets.append(Socket(
                        local_ip=local[0],
                        local_port=local[1],
                        remote_ip=remote[0],
                        remote_port=remote[1],
                        state=state,
                        process=process
                    ))
                except ValueError as e:
                    if verbose:
                        logging.warning(f"Skipping line due to parse error: {e}")
                    continue
        if verbose:
            logging.info(f"Read {len(sockets)} connections from {file_path}")
        return sockets
    except IOError as e:
        logging.error(f"Error reading {file_path}: {e}")
        return []

def read_all_connections(tcp_file: str, tcp6_file: str, verbose: bool) -> List[Socket]:
    """Read TCP and TCP6 connections concurrently"""
    queue = Queue()
    threads = []
    for file_path in [tcp_file, tcp6_file]:
        t = Thread(target=lambda fp, q, v: q.put(read_tcp_connections(fp, v)), args=(file_path, queue, verbose))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    sockets = []
    while not queue.empty():
        sockets.extend(queue.get())
    if verbose:
        logging.info(f"Total connections read: {len(sockets)}")
    return sockets

def check_permissions(file_paths: List[str]) -> None:
    """Check if the script has read access to the specified files"""
    if os.geteuid() != 0:
        for path in file_paths:
            if os.path.exists(path) and not os.access(path, os.R_OK):
                logging.error(f"Need root privileges to read {path}. Run with sudo.")
                exit(1)

def filter_sockets(sockets: List[Socket], args) -> List[Socket]:
    """Filter sockets based on command-line arguments"""
    filtered = sockets
    if args.state:
        state = args.state.upper()
        if state not in TCP_STATES.values():
            logging.error(f"Invalid state: {args.state}. Valid states: {', '.join(TCP_STATES.values())}")
            exit(1)
        filtered = [s for s in filtered if s.state == state]
    if args.local_ip:
        try:
            local_net = ipaddress.ip_network(args.local_ip, strict=False)
            filtered = [s for s in filtered if ipaddress.ip_address(s.local_ip) in local_net]
        except ValueError as e:
            logging.error(f"Invalid local IP/network: {args.local_ip}, error: {e}")
            return []
    if args.remote_ip:
        try:
            remote_net = ipaddress.ip_network(args.remote_ip, strict=False)
            filtered = [s for s in filtered if ipaddress.ip_address(s.remote_ip) in remote_net]
        except ValueError as e:
            logging.error(f"Invalid remote IP/network: {args.remote_ip}, error: {e}")
            return []
    if args.port:
        filtered = [s for s in filtered if s.local_port == args.port or s.remote_port == args.port]
    if args.process:
        filtered = [s for s in filtered if args.process.lower() in s.process.lower()]
    return filtered

def sort_sockets(sockets: List[Socket], sort_by: str) -> List[Socket]:
    """Sort sockets by the specified field"""
    if sort_by == "state":
        return sorted(sockets, key=lambda s: s.state)
    elif sort_by == "local_ip":
        return sorted(sockets, key=lambda s: ipaddress.ip_address(s.local_ip))
    elif sort_by == "remote_ip":
        return sorted(sockets, key=lambda s: ipaddress.ip_address(s.remote_ip))
    elif sort_by == "port":
        return sorted(sockets, key=lambda s: (s.local_port, s.remote_port))
    elif sort_by == "process":
        return sorted(sockets, key=lambda s: s.process)
    return sockets

def display_connections(sockets: List[Socket], output_format: str = "table", no_color: bool = False, compact_json: bool = False) -> None:
    """Display connections in the specified format"""
    if not sockets:
        print("No active TCP connections found")
        return
    
    if output_format == "json":
        indent = None if compact_json else 2
        print(json.dumps([s._asdict() for s in sockets], indent=indent))
        return
    
    # Calculate maximum lengths for dynamic column widths
    max_addr_len = max(len("Local Address"), len("Remote Address"))
    max_process_len = len("Process")
    for s in sockets:
        local_addr = f"{s.local_ip}:{s.local_port}"
        remote_addr = f"{s.remote_ip}:{s.remote_port}"
        max_addr_len = max(max_addr_len, len(local_addr), len(remote_addr))
        max_process_len = max(max_process_len, len(s.process))
    
    # Print header
    print("\nACTIVE TCP CONNECTIONS:")
    header = f"{'State':<15} {'Local Address':<{max_addr_len}} {'Remote Address':<{max_addr_len}} {'Process':<{max_process_len}}"
    print(header)
    print("-" * len(header))
    
    # Print each connection
    for s in sockets:
        local_addr = f"{s.local_ip}:{s.local_port}"
        remote_addr = f"{s.remote_ip}:{s.remote_port}"
        state = s.state if no_color or not sys.stdout.isatty() else STATE_COLORS.get(s.state, "{}").format(s.state)
        print(f"{state:<15} {local_addr:<{max_addr_len}} {remote_addr:<{max_addr_len}} {s.process:<{max_process_len}}")

def handle_sigint(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\nStopped monitoring")
    exit(0)

def main():
    # Check platform
    if platform.system() != "Linux":
        logging.error("This script requires Linux with /proc filesystem")
        exit(1)
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="TCP Connection Monitor",
        epilog=f"Valid states: {', '.join(TCP_STATES.values())}\nExample: sudo python3 tcp_monitor.py --watch 1 --state ESTABLISHED --local-ip 192.168.1.0/24"
    )
    parser.add_argument("--tcp-file", default="/proc/net/tcp", help="Path to TCP file")
    parser.add_argument("--tcp6-file", default="/proc/net/tcp6", help="Path to TCP6 file")
    parser.add_argument("--watch", type=float, default=0, help="Refresh interval in seconds (0 for single snapshot)")
    parser.add_argument("--state", help="Filter by connection state")
    parser.add_argument("--local-ip", help="Filter by local IP or subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("--remote-ip", help="Filter by remote IP or subnet")
    parser.add_argument("--port", type=int, help="Filter by local or remote port")
    parser.add_argument("--process", help="Filter by process name or PID")
    parser.add_argument("--sort", choices=["state", "local_ip", "remote_ip", "port", "process"], default="state", help="Sort by field")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--compact-json", action="store_true", help="Use compact JSON output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    # Check permissions
    check_permissions([args.tcp_file, args.tcp6_file])

    # Set up signal handling for watch mode
    if args.watch > 0:
        signal.signal(signal.SIGINT, handle_sigint)

    # Read and display connections
    clear_cmd = 'cls' if platform.system() == 'Windows' else 'clear'
    if args.watch > 0:
        while True:
            sockets = read_all_connections(args.tcp_file, args.tcp6_file, args.verbose)
            sockets = filter_sockets(sockets, args)
            sockets = sort_sockets(sockets, args.sort)
            os.system(clear_cmd)
            display_connections(sockets, args.format, args.no_color, args.compact_json)
            time.sleep(args.watch)
    else:
        sockets = read_all_connections(args.tcp_file, args.tcp6_file, args.verbose)
        sockets = filter_sockets(sockets, args)
        sockets = sort_sockets(sockets, args.sort)
        display_connections(sockets, args.format, args.no_color, args.compact_json)

if __name__ == "__main__":
    main()
