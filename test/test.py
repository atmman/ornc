#coding: utf-8

from pprint import pprint
from netaddr import IPNetwork
from netmap_builder.core.net_object import create_preconf_net_object, NetObjectType, FilterAction, FilterTable
from netmap_builder.core.netmap import create_preconf_net_map
#from netmap_builder.core.reachability import ReachabilityController
from netmap_builder.core.subnet import create_preconf_subnet
#from netmap_builder.core.service import create_preconf_service
from ReportParser import ReportParser
from CombineNetmapReport import combine_netmap_report

def create_test_netmap():

    netmap = create_preconf_net_map('BIT')

    subnet = create_preconf_subnet(netmap)
    subnet.name = 'BIT'
    subnet.cidr = '10.10.133.0/24'
    netmap.subnets.append(subnet)

    host_1 = create_preconf_net_object(net_obj_type=NetObjectType.host, subnet=subnet)
    host_1.interfaces[0].cidr = IPNetwork('10.10.133.2/24')
    host_1.interfaces[0].gateway = IPNetwork('10.10.133.1/24')
    subnet.net_objects.append(host_1)

    host_2 = create_preconf_net_object(net_obj_type=NetObjectType.host, subnet=subnet)
    host_2.interfaces[0].cidr = IPNetwork('10.10.133.3/24')
    host_2.interfaces[0].gateway = IPNetwork('10.10.133.1/24')
    subnet.net_objects.append(host_2)

    host_3 = create_preconf_net_object(net_obj_type=NetObjectType.host, subnet=subnet)
    host_3.interfaces[0].cidr = IPNetwork('10.10.133.4/24')
    host_3.interfaces[0].gateway = IPNetwork('10.10.133.1/24')
    subnet.net_objects.append(host_3)

    host_4 = create_preconf_net_object(net_obj_type=NetObjectType.host, subnet=subnet)
    host_4.interfaces[0].cidr = IPNetwork('10.10.133.11/24')
    host_4.interfaces[0].gateway = IPNetwork('10.10.133.1/24')
    subnet.net_objects.append(host_4)

    host_5 = create_preconf_net_object(net_obj_type=NetObjectType.host, subnet=subnet)
    host_5.interfaces[0].cidr = IPNetwork('10.10.133.21/24')
    host_5.interfaces[0].gateway = IPNetwork('10.10.133.1/24')
    subnet.net_objects.append(host_5)

    switch = create_preconf_net_object(net_obj_type=NetObjectType.switch, subnet=subnet)
    switch.name = 'switch'
    subnet.net_objects.append(switch)

    router = create_preconf_net_object(net_obj_type=NetObjectType.router, subnet=netmap.subnets[0])
    router.interfaces[0].cidr = IPNetwork('10.10.133.1/24')
    rule_list = ['-n 10.10.133.0/24 -g 10.10.133.1/24']
    router.set_routing_table('\n'.join(rule_list))
    netmap.routers.append(router)

    switch.connect(router)
    host_1.connect(switch)
    host_2.connect(switch)
    host_3.connect(switch)
    host_4.connect(switch)
    host_5.connect(switch)

    return netmap


def get_parsed_report(path):
    report = open(path, 'r').read()
    parser = ReportParser()

    return parser.parse_report(report)


if __name__ == '__main__':
    new_netmap = create_test_netmap()
    report_dict = get_parsed_report('/home/t/p//report_examples/test.xml')
    netmap_with_services = combine_netmap_report(new_netmap, report_dict)
    pprint(netmap_with_services.to_dict())

