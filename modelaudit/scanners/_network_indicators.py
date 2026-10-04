"""Shared classification of IP addresses found in model evidence."""

import ipaddress


def _is_public_ip(candidate: str) -> bool:
    try:
        value = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return not (value.is_private or value.is_loopback or value.is_link_local or value.is_multicast)
