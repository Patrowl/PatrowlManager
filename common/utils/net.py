from netaddr import IPNetwork, IPAddress, iter_iprange
from netaddr.core import AddrFormatError


def is_valid_ip(ip):
    try:
        IPAddress(ip)
    except (TypeError, ValueError, AddrFormatError):
        return False
    return True


def is_valid_subnet(subnet):
    try:
        IPNetwork(subnet)
    except (TypeError, ValueError, AddrFormatError):
        return False
    if "/" not in subnet:
        return False
    return True


def is_valid_ip_range(iprange):
    if iprange.count('-') != 1:
        return False
    if not iprange.split('-')[1].isdigit() or int(iprange.split('-')[1]) in range(0, 255):
        return False
    ip = iprange.split('-')
    return is_valid_ip(ip)


def is_ipaddr_in_subnet(ip, subnet):
    try:
        if IPAddress(ip) in IPNetwork(subnet):
            return True
    except (TypeError, ValueError, AddrFormatError):
        pass
    return False


def is_ipaddr_in_range(ip, range): # only support range for last digits
    if not is_valid_ip_range(range): return False

    start_range, end_range = range.split("-")
    if '.' not in end_range:
        end_range = "{}.{}".format('.'.join(start_range.split('.')[:3]), end_range)

    try:
        if IPAddress(ip) in list(iter_iprange(start_range, end_range)):
            return True
    except (TypeError, ValueError, AddrFormatError):
        pass
    return False


def is_ip_in_ipset(ip, ipset):
    #print "is_ip_in_ipset/ip:", ip
    #print "is_ip_in_ipset/ipset:", ipset
    if is_valid_subnet(ipset) and is_ipaddr_in_subnet(ip, ipset): return True
    if is_valid_ip_range(ipset) and is_ipaddr_in_range(ip, ipset): return True

    return False
