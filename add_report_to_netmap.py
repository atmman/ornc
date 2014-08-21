from netaddr import IPNetwork


def combine_netmap_report(netmap, report_dict):
    for subnet in netmap.subnets:
        for net_object in subnet.net_objects:
            for interface in net_object.interfaces:

                if not interface.cidr:
                    continue
                
                host_dict = report_dict.get(str(interface.cidr.ip))
                cve_list = host_dict['cve_list']

                for cve_item in cve_list:

                    new_service = add_service(net_object, cve_item)
                    if new_service:
                        new_service.vulnerabilities = get_vulnerabilities(cve_list, new_service.cpe)
    return netmap


def add_service(net_object, cve_item):
    cpe = cve_item.get('cpe') or cve_item.get('possible_cpe')
    if cpe in [service.cpe for service in net_object.services]:
        return None
    service = net_object.add_service()
    service.cpe = cpe
    service.port = cve_item['port']
    return service

def get_vulnerabilities(cve_list, cpe):
    vulns = [{'cve':cve_item.get('cve'), 'source':cve_item.get('source_type')}
             for cve_item in cve_list
             if cpe == cve_item.get('cpe') or cpe == cve_item.get('possible_cpe')]
    return vulns


