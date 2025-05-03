import logging
import struct

# Setup logging for invalid queries
invalid_query_logger = logging.getLogger('invalid_query_logger')
invalid_query_logger.setLevel(logging.WARNING)
invalid_handler = logging.FileHandler('invalid_queries.log', mode='a')
invalid_formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
invalid_handler.setFormatter(invalid_formatter)
invalid_query_logger.addHandler(invalid_handler)
invalid_query_logger.propagate = False

def parse_dns_query(data):
    """
    Parse a DNS query packet and return the query ID and domain name.
    
    Args:
        data (bytes): The raw DNS query packet
        
    Returns:
        tuple: (query_id, domain_name)
    """
    try:
        # Extract query ID (first 2 bytes)
        query_id = struct.unpack('!H', data[:2])[0]
        
        # Skip header (12 bytes) and parse domain name
        domain_parts = []
        pos = 12  # Skip DNS header
        
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            pos += 1
            try:
                part = data[pos:pos+length].decode('utf-8', errors='ignore')
                domain_parts.append(part)
            except Exception as e:
                invalid_query_logger.warning(f"Error parsing domain part at position {pos}: {str(e)}")
                return query_id, None
            pos += length
        
        domain = '.'.join(domain_parts)
        if not domain:  # Empty domain
            invalid_query_logger.warning("Empty domain name in query")
            return query_id, None
        return query_id, domain
    except Exception as e:
        invalid_query_logger.warning(f"Error parsing DNS query: {str(e)}")
        return None, None

def parse_domain_name(data, offset):
    """
    Parse a domain name from DNS packet data.
    
    Args:
        data (bytes): The raw DNS packet data
        offset (int): The starting offset in the data
        
    Returns:
        tuple: (domain_name, new_offset)
    """
    domain_parts = []
    while True:
        length = data[offset]
        if length == 0:
            return '.'.join(domain_parts), offset + 1
        if length & 0xC0 == 0xC0:  # This is a pointer
            pointer = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3FFF
            subdomain, _ = parse_domain_name(data, pointer)
            domain_parts.append(subdomain)
            return '.'.join(domain_parts), offset + 2
        offset += 1
        # Get the domain part and decode it properly
        part = data[offset:offset + length].decode('ascii', errors='ignore')
        domain_parts.append(part)
        offset += length