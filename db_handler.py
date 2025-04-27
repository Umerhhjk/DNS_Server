import sqlite3
import os

class DNSDatabase:
    def __init__(self, db_file='dns_records.db'):
        self.db_file = db_file
        self.init_db()

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
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO dns_records (domain, ip_address, record_type, ttl)
                VALUES (?, ?, ?, ?)
            ''', (domain, ip_address, record_type, ttl))
            conn.commit()
        finally:
            conn.close()

    def lookup_domain(self, domain):
        """Look up a domain in the database and return its IP address."""
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
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM dns_records WHERE domain = ?', (domain,))
            conn.commit()
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