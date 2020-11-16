# -*- coding: utf-8 -*-

from netaddr import IPNetwork, IPAddress, iter_iprange
from netaddr.core import AddrFormatError
import re


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


def is_ipaddr_in_range(ip, range):  # only support range for last digits
    if not is_valid_ip_range(range):
        return False

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
    if is_valid_subnet(ipset) and is_ipaddr_in_subnet(ip, ipset):
        return True
    if is_valid_ip_range(ipset) and is_ipaddr_in_range(ip, ipset):
        return True

    return False


def _is_valid_domain(domain):
    pattern = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
    )
    return pattern.match(str(domain))


def _is_valid_url(url):
    ip_middle_octet = u"(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5]))"
    ip_last_octet = u"(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))"

    pattern = re.compile(
        u"^"
        # protocol identifier
        u"(?:(?:https?|ftp)://)"
        # user:pass authentication
        u"(?:\S+(?::\S*)?@)?"
        u"(?:"
        u"(?P<private_ip>"
        # IP address exclusion
        # private & local networks
        u"(?:(?:10|127)" + ip_middle_octet + u"{2}" + ip_last_octet + u")|"
        u"(?:(?:169\.254|192\.168)" + ip_middle_octet + ip_last_octet + u")|"
        u"(?:172\.(?:1[6-9]|2\d|3[0-1])" + ip_middle_octet + ip_last_octet + u"))"
        u"|"
        # IP address dotted notation octets
        # excludes loopback network 0.0.0.0
        # excludes reserved space >= 224.0.0.0
        # excludes network & broadcast addresses
        # (first & last IP address of each class)
        u"(?P<public_ip>"
        u"(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])"
        u"" + ip_middle_octet + u"{2}"
        u"" + ip_last_octet + u")"
        u"|"
        # host name
        u"(?:(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)"
        # domain name
        u"(?:\.(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)*"
        # TLD identifier
        u"(?:\.(?:[a-z\u00a1-\uffff]{2,}))"
        u")"
        # port number
        u"(?::\d{2,5})?"
        # resource path
        u"(?:/\S*)?"
        # query string
        u"(?:\?\S*)?"
        u"$",
        re.UNICODE | re.IGNORECASE
    )
    return pattern.match(str(url))


def is_valid_email(email):
    from django.core.validators import validate_email
    from django.core.exceptions import ValidationError
    try:
        validate_email(email)
        return True
    except ValidationError:
        return False
