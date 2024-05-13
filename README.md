# PyForcer

SSH, or as some others may know it, OpenSSH, is a secure shell daemon that does exactly what the name suggests, it provides you a secure shell to your machine over the internet. While OpenSSH has demonstrated inherit flaws with it's underlying code in the past; What continues to remain the bane of existence for blue teaming? Brute forcing. I was pretty unsatisified with what I saw on GitHub for brute forcing, so I decided to tackle this project myself as if I were a red teamer, this is my creation:

PyForcer is an secure shell (SSH) brute forcing tool that is focused on speed and validity. Keeping those things in mind, I've also decided to add a feature I've not seen other bruteforcers have. The ability to use private keys alongside user:pass combinations. This greatly increases chances of target surface depending on the situation. While some methods employed by other bruteforcers are impelemented rudimentary, such as detecting the output of pre-selected commands that bare universal resemblence across target systems. At this time there is no way to distinguish from honeypots and real targets (soon tm). Please read further below on usage specifications and known issues. This repository is now public and might receive future updates, however it's not high on my priority list at this time. Please be responsible and enjoy.

As always, if you find any bugs, feel free to submit an issue, pull requests are also welcome. 

## Dependencies

- Python 3.0
- ipaddress module
- paramiko module
- argparse

## Usage

The script is executed from the command line, with the following syntax:

./pyforcer.py X.X.X.X/file outfile --port --creds --threads --keyfile


The arguments are as follows:

- [input] [IP:ip/cidr:port|IP:ip:port|FILE:<filename> <syntax:ip:port>|FILE:<filename> <syntax:ip/cidr:port>|] - Various data interpretation modes.
- [output_file] - The name of the file to which the results will be written.
- [creds] [user:pass:keyfile(optional)] <credentials_file> - The name of the file containing the login credentials to check. It should have one set of credentials per line, in the format username:password:keyfile, the keyfile is optional. If this option is not specified, the script will look for a file named credentials.txt in the current directory.
- --interface: <interface-name> - Optional, specifies the network interface to use, defaults to eth0.
- --cmd: Command to run after successful login (default: uname -a) 
- --threads: - The amount of threads you wish to specify to run concurrently. (default: 32)
- --debug: - Enable the script's various debugging features

## Known Issues
- Scanning large ranges of IP space might consume most, if not all system memory due to the way IP address caching is done at this time. (16GB RAM Theoretical max but I've seen worse & crashed systems.)
- You might run into duplicate IP addresses if you are not careful about how you label your CIDRs, try not to overlap ranges, there is no sanity checking for this.

## Disclaimer

**IT IS ILLEGAL TO ACCESS A COMPUTER SYSTEM YOU HAVE NOT SOUGHT OUT PRIOR AUTHORIZATION TO DO SO, THIS IS A FEDERAL CRIME.**
The developer is not responsible for any harm caused from the usage of this tool, please exercise caution and understand you may be breaking the law when using this tool.
