import struct

def parse_dns_query(data):
    """
    Parse a DNS query packet and return the query ID and domain name.
    
    Args:
        data (bytes): The raw DNS query packet
        
    Returns:
        tuple: (query_id, domain_name)
    """
    # Extract the query ID (first 2 bytes)
    query_id = struct.unpack('!H', data[0:2])[0]
    
    # Skip the header (12 bytes)
    offset = 12
    
    # Parse the domain name
    domain_parts = []
    while True:
        length = data[offset]
        if length == 0:
            break
        offset += 1
        domain_parts.append(data[offset:offset + length].decode('ascii'))
        offset += length
    
    domain = '.'.join(domain_parts)
    
    return query_id, domain

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
        domain_parts.append(data[offset:offset + length].decode('ascii'))
        offset += length 