# Simple HTTPS Honeypot Server

## Introduction
The Simple HTTPS Honeypot Server is a cybersecurity tool aimed at emulating a secure web server (HTTPS) to monitor and analyze encrypted web traffic. It uses Python and the Twisted framework to simulate a secure server environment, complete with self-signed SSL certificates. This server is crucial for understanding HTTPS vulnerabilities and potential intrusion methods.

## Features
- **HTTPS Server Emulation**: Mimics a secure web server to log HTTPS requests.
- **Self-Signed SSL Certificates**: Generates self-signed SSL certificates to mimic secure connections.
- **Resource Inlining**: Downloads and adjusts external resources like CSS, JS, and images for realistic emulation.
- **Extensive Logging**: Records all HTTPS requests, including headers, client IP, and requested paths.
- **Real-Time Monitoring**: Instant insights into HTTPS traffic for suspicious activity detection.
- **Educational Resource**: Great for studying web security in encrypted environments.

## Beta Version Notice
- **Beta Version**: This script is currently in beta. It may not fully support all websites or web services. Contributions and pull requests are welcome!

## Requirements
- Python 3.x
- Twisted Python library
- BeautifulSoup4 Python library
- Requests Python library
- Cryptography Python library

## Installation
Set up the HTTPS honeypot server with these steps:

```bash
git clone https://github.com/0xNslabs/https-honeypot.git
cd https-honeypot
pip install twisted beautifulsoup4 requests cryptography
```

## Usage
Run the server with the necessary arguments for host, port, SSL configuration, and target URL:

```bash
python3 https.py --host 0.0.0.0 --port 443 --url "https://example.com" --ssl_country "US" --ssl_state "CA" --ssl_locality "San Francisco" --ssl_org "NeroTeam Security Labs" --domain_name "localhost"
```

## Logging
Logs are saved in https_honeypot.log, containing detailed records of HTTPS requests and interactions.

## Simple HTTPS Honeypot in Action
![Simple HTTPS Honeypot in Action](https://raw.githubusercontent.com/0xNslabs/https-honeypot/main/PoC.png)
*This image illustrates the Simple HTTPS Honeypot Server capturing real-time HTTPS requests.*

## Other Simple Honeypot Services

Check out the other honeypot services for monitoring various network protocols:

- [DNS Honeypot](https://github.com/0xNslabs/dns-honeypot) - Monitors DNS interactions.
- [FTP Honeypot](https://github.com/0xNslabs/ftp-honeypot) - Simulates an FTP server.
- [LDAP Honeypot](https://github.com/0xNslabs/ldap-honeypot) - Mimics an LDAP server.
- [HTTP Honeypot](https://github.com/0xNslabs/http-honeypot) - Monitors HTTP interactions.
- [HTTPS Honeypot](https://github.com/0xNslabs/https-honeypot) - Monitors HTTPS interactions.
- [NTP Honeypot](https://github.com/0xNslabs/ntp-honeypot) - Monitors Network Time Protocol interactions.
- [PostgreSQL Honeypot](https://github.com/0xNslabs/postgresql-honeypot) - Simulates a PostgreSQL database server.
- [SIP Honeypot](https://github.com/0xNslabs/sip-honeypot) - Monitors SIP (Session Initiation Protocol) interactions.
- [SSH Honeypot](https://github.com/0xNslabs/ssh-honeypot) - Emulates an SSH server.
- [TELNET Honeypot](https://github.com/0xNslabs/telnet-honeypot) - Simulates a TELNET server.

## Security and Compliance
- **Caution**: Operate this honeypot within secure, controlled settings for research and learning purposes.
- **Compliance**: Deploy this honeypot in accordance with local and international legal and ethical standards.

## License
This project is available under the MIT License. See the LICENSE file for more information.