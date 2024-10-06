
import ipaddress
import logging
LOGGER = logging.getLogger('my_logger')
def cidr_to_netmask(cidr):
    # shift 1 left (inserting zeros) for cidr count
    # subtract 1 causing all the bits below the shifted 1 to flip
    # XOR to invert every bit, making the host portion 0's
    bits = 0xffffffff ^ (1 << 32 - int(cidr)) - 1
    # To make each octet, shift it right then use AND to cut off anything more than last 8
    return f"{(bits >> 24) & 0xff}.{(bits >> 16) & 0xff}.{(bits >> 8) & 0xff}.{bits & 0xff}"

def cidr_to_wildmask(cidr):
    # shift 1 left (inserting zeros) for cidr count
    # subtract 1 causing all the bits below the shifted 1 to flip
    bits = (1 << 32 - int(cidr)) - 1
    # To make each octet, shift it right then use AND to cut off anything more than last 8
    return f"{(bits >> 24) & 0xff}.{(bits >> 16) & 0xff}.{(bits >> 8) & 0xff}.{bits & 0xff}"

def netmask_to_cidr(netmask):
    # Count the number of ones per each octet and sum total
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def ipv4_netid(addr,cidr):
    import ipaddress
    if not (0 <= cidr <= 31):
        LOGGER.error("Error converting: CIDR must be between 0 and 31.")

    # shift 1 left (inserting zeros) for cidr count
    # subtract 1 causing all the bits below the shifted 1 to flip
    # XOR to invert every bit, making the host portion 0's and subnet 1's
    bits = 0xffffffff ^ (1 << 32 - int(cidr)) - 1
    try:
        # Convert IP address string to integer
        ip_int = int(ipaddress.IPv4Address(addr))
    except ipaddress.AddressValueError as ave:
        LOGGER.error(f"Error converting: Invalid IPv4 address '{addr}': {ave}")
    # use AND to mask low the host portion of given address
    net = ip_int & bits
    # To make each octet, shift it right then use AND to cut off anything more than last 8
    return f"{(net >> 24) & 0xff}.{(net >> 16) & 0xff}.{(net >> 8) & 0xff}.{net & 0xff}"

def ipv4_broadcast(addr,cidr):
    import ipaddress
    if not (0 <= cidr <= 31):
        LOGGER.error("Error converting: CIDR must be between 0 and 31.")
    # divide ip as int by (2 to the power of 32 - cidr)
    # round down to a whole number then add 1
    # 
    # shift 1 left (inserting zeros) for cidr count
    # subtract 1 causing all the bits below the shifted 1 to flip
    bits = (1 << 32 - int(cidr)) - 1
    try:
        # Convert IP address string to integer
        ip_int = int(ipaddress.IPv4Address(addr))
    except ipaddress.AddressValueError as ave:
        LOGGER.error(f"Error converting: Invalid IPv4 address '{addr}': {ave}")
    # use OR to mask high the host portion of given address
    net = ip_int | bits
    # To make each octet, shift it right then use AND to cut off anything more than last 8
    return f"{(net >> 24) & 0xff}.{(net >> 16) & 0xff}.{(net >> 8) & 0xff}.{net & 0xff}"