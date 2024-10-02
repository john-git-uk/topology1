#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule

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
    if not (0 <= cidr <= 30):
        raise ValueError("CIDR must be between 0 and 30.")

    # shift 1 left (inserting zeros) for cidr count
    # subtract 1 causing all the bits below the shifted 1 to flip
    # XOR to invert every bit, making the host portion 0's and subnet 1's
    bits = 0xffffffff ^ (1 << 32 - int(cidr)) - 1
    try:
        # Convert IP address string to integer
        ip_int = int(ipaddress.IPv4Address(addr))
    except ipaddress.AddressValueError as ave:
        raise ValueError(f"Invalid IPv4 address '{addr}': {ave}")
    # use AND to mask low the host portion of given address
    net = ip_int & bits
    # To make each octet, shift it right then use AND to cut off anything more than last 8
    return f"{(net >> 24) & 0xff}.{(net >> 16) & 0xff}.{(net >> 8) & 0xff}.{net & 0xff}"

def ipv4_broadcast(addr,cidr):
    import ipaddress
    if not (0 <= cidr <= 30):
        raise ValueError("CIDR must be between 0 and 30.")
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
        raise ValueError(f"Invalid IPv4 address '{addr}': {ave}")
    # use OR to mask high the host portion of given address
    net = ip_int | bits
    # To make each octet, shift it right then use AND to cut off anything more than last 8
    return f"{(net >> 24) & 0xff}.{(net >> 16) & 0xff}.{(net >> 8) & 0xff}.{net & 0xff}"

def main():
    import ipaddress
    twentyfour = f"255.255.255.0"
    module_args = dict(
        what=dict(type='str', required=False),
        cidr=dict(type='int', required=False),
        netmask=dict(type='str', required=False),
        addr=dict(type='str', required=False),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    what = module.params['what']
    cidr = module.params['cidr']
    netmask = module.params['netmask']
    addr = module.params['addr']
    try:
        match what:
            case "cidr_to_netmask":
                result_val = cidr_to_netmask(cidr)
                result = dict(
                    changed=False,
                    what=what,
                    cidr=cidr,
                    netmask=netmask,
                    addr=addr,
                    result_val=result_val,
                )
            case "cidr_to_wildmask":
                result_val = cidr_to_wildmask(cidr)
                result = dict(
                    changed=False,
                    what=what,
                    cidr=cidr,
                    netmask=netmask,
                    addr=addr,
                    result_val=result_val,
                )
            case "netmask_to_cidr":
                try:
                    ipaddress.IPv4Network(f"0.0.0.0/{netmask}")
                except ipaddress.NetmaskValueError as nmve:
                    module.fail_json(msg=f"Invalid netmask '{netmask}': {nmve}")
                result_val=netmask_to_cidr(netmask)
                result = dict(
                    changed=False,
                    what=what,
                    cidr=cidr,
                    netmask=netmask,
                    addr=addr,
                    result_val=result_val,
                )
            case "ipv4_netid":
                try:
                    ipaddress.IPv4Address(addr)
                except ipaddress.AddressValueError as ave:
                    module.fail_json(msg=f"Invalid IPv4 address '{addr}': {ave}")
                result_val=ipv4_netid(addr,cidr)
                result = dict(
                    changed=False,
                    what=what,
                    cidr=cidr,
                    netmask=netmask,
                    addr=addr,
                    result_val=result_val,
                )
            case "ipv4_broadcast":
                try:
                    ipaddress.IPv4Address(addr)
                except ipaddress.AddressValueError as ave:
                    module.fail_json(msg=f"Invalid IPv4 address '{addr}': {ave}")
                result_val=ipv4_broadcast(addr,cidr)
                result = dict(
                    changed=False,
                    what=what,
                    cidr=cidr,
                    netmask=netmask,
                    addr=addr,
                    result_val=result_val,
                )
            case _:
                module.fail_json(msg='Requested function not recognised.')

    except ValueError as ve:
        module.fail_json(msg=str(ve))
    except Exception as e:
        module.fail_json(msg=f"An unexpected error occurred: {str(e)}")

    module.exit_json(**result)

if __name__ == '__main__':
    main()
