# Python DNS Server

A simple DNS server implementation in Python that uses manual query parsing and SQLite for storage.

## Features

- Manual DNS query parsing without external libraries
- SQLite database for DNS record storage
- Support for A records
- Simple and Extensible Architecture

## Usage

1. Start the DNS server:
```bash
python dns_server.py
```

2. Add DNS records to the Database, to test:
```python
from db_handler import DNSDatabase

db = DNSDatabase()
db.add_record('example.com', '192.168.1.1')
```

3. Test the DNS server using dig or nslookup:
```bash
dig @localhost example.com
```

**Sample Output (Bash/Linux/macOS):**
```bash
$ dig @localhost example.com

; <<>> DiG 9.18.1 <<>> @localhost example.com
; (1 server found)
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;example.com.                  IN      A

;; ANSWER SECTION:
example.com.            3600    IN      A       192.168.1.100

;; Query time: 1 msec
;; SERVER: 127.0.0.1#53(localhost)
;; WHEN: Thu Mar 14 15:30:45 UTC 2024
;; MSG SIZE  rcvd: 56
```
```cmd
nslookup google.com 127.0.0.1
```
**Sample Output (Windows CMD):**
```
C:\>nslookup google.com 127.0.0.1
Server:  localhost
Address:  127.0.0.1

Name:    google.com
Address: 142.250.190.78
```

## Note

This is a Basic Implementation and does not Support all DNS Features. It's Intended for Learning as course
Project for Computer Networks

## Improvements

Here are some improvements and features that can be added to this DNS server:

- **Support for more record types:** Add support for AAAA (IPv6), MX (mail), CNAME, TXT, PTR, and other DNS record types.
- **Reverse DNS (PTR) support:** Allow the server to answer reverse lookup queries (e.g., `in-addr.arpa`).
- **Zone file import/export:** Allow importing/exporting DNS records from standard zone files.
- **Web or CLI management interface:** Provide a user-friendly way to add, remove, or update DNS records.
- **DNSSEC support:** Implement DNS Security Extensions for secure DNS responses.
- **Rate limiting and security:** Add rate limiting, query validation, and protection against DNS amplification attacks.
- **Configuration file:** Allow server settings (port, database path, etc.) to be set via a config file.
- **Dynamic updates:** Support for dynamic DNS updates (RFC 2136).
- **IPv6 support:** Allow the server to listen on IPv6 addresses and handle AAAA records.
- **Better error handling:** Improve error messages and robustness for malformed queries.