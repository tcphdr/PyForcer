# PyForcer

PyForcer is a Python script that checks for SSH logins on specified IP addresses and writes the results to a file. It is compatible with both Python 2.7 and 3.0.

## Dependencies

- Python 2.7 or 3.0
- ipaddress module
- paramiko module
- socks module (optional)

## Usage

The script is executed from the command line, with the following syntax:

python PyForcer.py [ip|cidr] [output_file] [--creds <credentials_file>] [--socks <socks_host> <socks_port>] [--debug]


The arguments are as follows:

- [ip|cidr] - Either a single IP address, or a CIDR block specifying a range of IP addresses to check.
- [output_file] - The name of the file to which the results will be written.
- --creds <credentials_file> (optional) - The name of the file containing the login credentials to check. The file should have one set of credentials per line, in the format username:password. If this option is not specified, the script will look for a file named credentials.txt in the current directory.
- --socks <socks_host> <socks_port> (optional) - The hostname and port number of a SOCKS proxy server to use when connecting to the IP addresses. If this option is not specified, the script will not use a proxy.
- --debug (optional) - If specified, the script will print debugging information to the console.

## How it works

### Step 1: Parsing the IP addresses

The script first reads in the IP address or CIDR block specified by the user. If a CIDR block is specified, the get_hosts_in_cidr function from the ipaddress module is used to generate a list of all the individual IP addresses in the block. If a single IP address is specified, the get_hosts_in_ip function is used to create a list containing just that address.

### Step 2: Reading the login credentials

The script then reads in the login credentials from the file specified by the user (or from credentials.txt if not specified). The file should have one set of credentials per line, in the format username:password. The script reads in the entire file and splits it into a list of credentials.

### Step 3: Testing the logins

The script then loops over each IP address in the list and each set of credentials in the list, calling the test_ssh_login function for each combination. This function creates a paramiko SSH client object and attempts to connect to the specified IP address using the specified credentials. If the connection is successful, the function submits a command to the SSH connection to retrieve system information from the remote host. The output from this command is discarded, but the fact that the command was successfully executed indicates that the login was successful.

### Step 4: Writing the output

Whenever a successful login is found, the script writes the IP address, username, and password to the output file specified by the user. The output file is opened and closed once for each successful login, so if there are multiple successful logins the file may be opened and closed multiple times.

### Step 5: Threading the processing

To speed up the processing of a large list of IP addresses, the script creates a number of worker threads (defaulting to 10) and assigns each thread a portion of the IP address list to process. This allows multiple logins to be tested simultaneously, increasing the speed of the overall process.