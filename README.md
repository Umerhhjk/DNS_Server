# Python DNS Server

A simple DNS server implementation in Python that uses manual query parsing and SQLite for storage.

## Features

- Manual DNS query parsing without external libraries
- SQLite database for DNS record storage
- Support for A records
- Simple and extensible architecture

## Requirements

- Python 3.6 or higher
- No external dependencies required

## Usage

1. Start the DNS server:
```bash
python dns_server.py
```

2. Add DNS records to the database:
```python
from db_handler import DNSDatabase

db = DNSDatabase()
db.add_record('example.com', '192.168.1.1')
```

3. Test the DNS server using dig or nslookup:
```bash
dig @localhost example.com
```

## Note

This is a basic implementation and may not support all DNS features. It's intended for educational purposes and simple use cases.
