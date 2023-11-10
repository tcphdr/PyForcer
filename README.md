# PyForcer

PyForcer is a Python script that checks for SSH logins on specified IP addresses and writes the results to a file. It is compatible with both Python 2.7 and 3.0.

## Dependencies

- Python 2.7 or 3.0
- ipaddress module
- paramiko module

## Usage

The script is executed from the command line, with the following syntax:

./pyforcer.py X.X.X.X/file outfile --port --creds --threads --keyfile


The arguments are as follows:

- [ip|file|cidr] - Either a single IP address, IP CIDR range, or a list of IPs to check
- [output_file] - The name of the file to which the results will be written.
- --creds: <credentials_file> - The name of the file containing the login credentials to check. The file should have one set of credentials per line, in the format username:password. If this option is not specified, the script will look for a file named credentials.txt in the current directory.
- --port: <Port> - The port in which you wish to attempt SSH credential bruteforcing from
- --keyfile: <Path to RSA/DSA/ECDSA keyfile> - Optional, specify a key file to use with the username combinations.
- --cmd: Command to run after successful login (default: uname -a) 
- --threads: - The amount of threads you wish to specify to run concurrently.
- --debug: - Enable the script's various debugging features
## Disclaimer

The developer is not responsible for any harm caused from the usage of this tool, please exercise caution and understand you may be breaking the law when using this tool.
