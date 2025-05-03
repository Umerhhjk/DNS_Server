import socket
import sys
import threading

from db_handler import DNSDatabase
from dns_parser import parse_dns_query


class DNSServer:
    def __init__(self, host='127.0.0.1', port=53, forward_dns='8.8.8.8', forward_port=53):
        self.host = host
        self.port = port
        self.forward_dns = forward_dns
        self.forward_port = forward_port
        self.db = DNSDatabase()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        print(f"DNS Server Running on {self.host}:{self.port}")
        print(f"Forwarding unknown queries to {self.forward_dns}:{self.forward_port}")

    def start(self):
        while self.running:
            try:
                self.socket.settimeout(1.0)  # So we can check self.running periodically
                try:
                    data, addr = self.socket.recvfrom(512)  # DNS messages are limited to 512 bytes
                except socket.timeout:
                    continue
                print(f"\nReceived query from {addr[0]}:{addr[1]}")
                
                query_id, domain = parse_dns_query(data)
                if domain is None:  # Invalid query was logged by parser
                    response = self.create_not_found_response(data, query_id)
                    self.socket.sendto(response, addr)
                    continue
                    
                print(f"Query ID: {query_id}")
                print(f"Domain: {domain}")
                
                # First try local database
                ip_address = self.db.lookup_domain(domain)
                
                if ip_address:
                    print(f"Found IP in local database: {ip_address}")
                    response = self.create_response(data, query_id, domain, ip_address)
                else:
                    print(f"Domain not found in local database, forwarding to {self.forward_dns}")
                    try:
                        response = self.forward_query(data)
                        print("Received response from forward DNS server")
                        # Store the forwarded response in database
                        self.store_forwarded_response(domain, response)
                    except Exception as e:
                        print(f"Error forwarding query: {e}")
                        response = self.create_not_found_response(data, query_id)
                
                self.socket.sendto(response, addr)
                print(f"Sent response to {addr[0]}:{addr[1]}")
                
            except Exception as e:
                print(f"Error handling query: {e}")
        self.socket.close()
        print("DNS Server shut down.")

    def store_forwarded_response(self, domain, response):
        """
        Store a forwarded DNS response in the database and log it.
        
        Args:
            domain (str): The domain name
            response (bytes): The DNS response packet
        """
        try:
            # Extract IP address from the response packet
            # The IP address is in the last 4 bytes of the response
            ip_bytes = response[-4:]
            ip_address = '.'.join(str(b) for b in ip_bytes)
            
            # Store in database (logging is handled by the database)
            if self.db.add_record(domain, ip_address):
                print(f"Stored forwarded response for {domain} -> {ip_address} in database")
        except Exception as e:
            print(f"Error storing forwarded response: {e}")

    def stop(self):
        self.running = False
        # Clear all forwarded responses from database
        self.db.clear_forwarded_responses()
        print("Cleared forwarded responses from database")

    def handle_query(self, data):
        query_id, domain = parse_dns_query(data)
        
        # First try local database
        ip_address = self.db.lookup_domain(domain)
        
        if ip_address:
            # Create a response with the IP address
            response = self.create_response(data, query_id, domain, ip_address)
        else:
            # If not found locally, try forwarding
            try:
                response = self.forward_query(data)
            except Exception as e:
                print(f"Error forwarding query: {e}")
                response = self.create_not_found_response(data, query_id)
        
        return response

    def forward_query(self, query_data):
        """
        Forward a DNS query to another DNS server.
        
        Args:
            query_data (bytes): The original DNS query packet
            
        Returns:
            bytes: The response from the forwarded DNS server
        """
        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward_socket.settimeout(5.0)  # 5 second timeout for forwarding
        
        try:
            # Send query to forward DNS server
            forward_socket.sendto(query_data, (self.forward_dns, self.forward_port))
            print(f"Forwarded query to {self.forward_dns}:{self.forward_port}")
            
            # Receive response
            response, _ = forward_socket.recvfrom(512)
            return response
            
        except socket.timeout:
            print("Timeout while waiting for forward DNS response")
            raise
        except Exception as e:
            print(f"Error during forwarding: {e}")
            raise
        finally:
            forward_socket.close()

    def create_response(self, original_query, query_id, domain, ip_address):
        """
        Create a proper DNS response packet.
        
        Args:
            original_query (bytes): The original query packet
            query_id (int): The query ID from the original query
            domain (str): The domain name being queried
            ip_address (str): The IP address to return
            
        Returns:
            bytes: The complete DNS response packet
        """
        # Start with the original query up to the question section
        response = bytearray(original_query)
        
        # Update the header
        # Set QR=1 (Response), AA=1 (Authoritative), RA=1 (Recursion Available)
        response[2] = 0x84  # QR=1, AA=1
        response[3] = 0x80  # RA=1
        
        # Set the number of answers to 1
        response[6] = 0x00
        response[7] = 0x01
        
        # Find the end of the question section
        question_end = 12  # Start after header
        while response[question_end] != 0:
            question_end += response[question_end] + 1
        question_end += 5  # Include the final null byte and QTYPE/QCLASS
        
        # Keep only the header and question section
        response = response[:question_end]
        
        # Convert IP address to bytes
        ip_bytes = bytes([int(x) for x in ip_address.split('.')])
        
        # Add the answer section
        # Name pointer to the question
        response.extend(b'\xC0\x0C')  # Pointer to the domain name in the question section
        
        # Type (A record = 1)
        response.extend(b'\x00\x01')
        
        # Class (IN = 1)
        response.extend(b'\x00\x01')
        
        # TTL (3600 seconds = 1 hour)
        response.extend(b'\x00\x00\x0E\x10')
        
        # RDATA length (4 bytes for IPv4)
        response.extend(b'\x00\x04')
        
        # RDATA (IP address)
        response.extend(ip_bytes)
        
        return bytes(response)

    def create_not_found_response(self, original_query, query_id):
        """
        Create a DNS response packet for when the domain is not found.
        """
        response = bytearray(original_query)
        
        # Set QR=1 (Response), AA=1 (Authoritative)
        response[2] = 0x84
        
        # Set RCODE=3 (Name Error)
        response[3] = 0x83
        
        # Find the end of the question section
        question_end = 12  # Start after header
        while response[question_end] != 0:
            question_end += response[question_end] + 1
        question_end += 5  # Include the final null byte and QTYPE/QCLASS
        
        # Keep only the header and question section
        response = response[:question_end]
        
        return bytes(response)

if __name__ == "__main__":
    server = DNSServer()
    server_thread = threading.Thread(target=server.start)
    server_thread.start()
    print("Press 'q' then Enter to quit.")
    while True:
        user_input = sys.stdin.readline().strip()
        if user_input.lower() == 'q':
            server.stop()
            server_thread.join()
            break 