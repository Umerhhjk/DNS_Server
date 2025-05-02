import logging
import os
import re
import sqlite3


class DNSDatabase:
    def __init__(self, db_file='dns_records.db'):
        self.db_file = db_file
        self.setup_logging()
        self.init_db()

    def setup_logging(self):
        """Setup logging configuration for invalid queries."""
        logging.basicConfig(
            filename='invalid_queries.log',
            level=logging.WARNING,
            format='%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def validate_domain(self, domain):
        """Validate domain name format."""
        # Basic domain name validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        if not re.match(domain_pattern, domain):
            logging.warning(f"Invalid domain name format: {domain}")
            return False
        return True

    def validate_ip(self, ip_address):
        """Validate IP address format."""
        # Basic IP address validation
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip_address):
            logging.warning(f"Invalid IP address format: {ip_address}")
            return False
        
        # Check if each octet is between 0 and 255
        try:
            octets = ip_address.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        except ValueError:
            logging.warning(f"Invalid IP address format: {ip_address}")
            return False

    def validate_record_type(self, record_type):
        """Validate DNS record type."""
        valid_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
        if record_type not in valid_types:
            logging.warning(f"Invalid record type: {record_type}")
            return False
        return True

    def validate_ttl(self, ttl):
        """Validate TTL value."""
        try:
            ttl = int(ttl)
            if ttl < 0 or ttl > 2147483647:  # Max 32-bit integer
                logging.warning(f"Invalid TTL value: {ttl}")
                return False
            return True
        except ValueError:
            logging.warning(f"Invalid TTL value: {ttl}")
            return False

    def init_db(self):
        """Initialize the database with the required table and sample records."""
        if not os.path.exists(self.db_file):
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Create the table
            cursor.execute('''
                CREATE TABLE dns_records (
                    domain TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    record_type TEXT DEFAULT 'A',
                    ttl INTEGER DEFAULT 3600
                )
            ''')
            
            # Sample records
            sample_records = [
                # Made-up domains
                ('example.com', '192.168.1.100', 'A', 3600),
                ('test.local', '10.0.0.50', 'A', 3600),
                ('dev.net', '172.16.0.25', 'A', 3600),
                
                # Real domains (Google)
                ('google.com', '142.250.190.78', 'A', 3600),
                ('www.google.com', '142.250.190.78', 'A', 3600),
                
                # Real domains (Facebook)
                ('facebook.com', '157.240.2.35', 'A', 3600),
                ('www.facebook.com', '157.240.2.35', 'A', 3600)
            ]
            
            # Insert sample records
            cursor.executemany('''
                INSERT INTO dns_records (domain, ip_address, record_type, ttl)
                VALUES (?, ?, ?, ?)
            ''', sample_records)
            
            conn.commit()
            conn.close()
            print("Database initialized with sample records")

    def add_record(self, domain, ip_address, record_type='A', ttl=3600):
        """Add a new DNS record to the database."""
        if not all([
            self.validate_domain(domain),
            self.validate_ip(ip_address),
            self.validate_record_type(record_type),
            self.validate_ttl(ttl)
        ]):
            return False

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO dns_records (domain, ip_address, record_type, ttl)
                VALUES (?, ?, ?, ?)
            ''', (domain, ip_address, record_type, ttl))
            conn.commit()
            return True
        finally:
            conn.close()

    def lookup_domain(self, domain):
        """Look up a domain in the database and return its IP address."""
        if not self.validate_domain(domain):
            return None

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT ip_address FROM dns_records WHERE domain = ?', (domain,))
            result = cursor.fetchone()
            return result[0] if result else None
        finally:
            conn.close()

    def delete_record(self, domain):
        """Delete a DNS record from the database."""
        if not self.validate_domain(domain):
            return False

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM dns_records WHERE domain = ?', (domain,))
            conn.commit()
            return True
        finally:
            conn.close()

    def list_all_records(self):
        """List all DNS records in the database."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT * FROM dns_records')
            return cursor.fetchall()
        finally:
            conn.close() 