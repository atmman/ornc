# coding=utf8
from netaddr import IPNetwork

_cidr = '10.10.0.0/24'
change = 0

def generate_cidr():
    global _first_cidr
    global change
    ip = IPNetwork(_cidr)
    _ip = str(ip.ip).split('.')

    change += 1
    _ip[2] = str(change)


    return  _ip

