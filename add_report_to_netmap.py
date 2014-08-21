from netaddr import IPNetwork


def combine_netmap_report(netmap, report_dict):
    for subnet in netmap.subnets:
        for net_object in subnet.net_objects:
            for interface in net_object.interfaces:

                if not interface.cidr:
                    continue
                
                host_dict = report_dict.get(str(interface.cidr.ip))
                cve_list = host_dict['cve_list']
                '''
                for cpe_item in host_dict.get('cpe_list'):
                    new_service = add_service(net_object, cpe_item)
                    new_service.vulnerabilities = get_vulnerabilities(host_dict['cve_list'], new_service.cpe)

                for cve_item in host_dict.get('cve_list'):
                    if not cve_item.get('possible_cpe'):
                        continue
                    if cve_item.get('possible_cpe') in [service.cpe for service in net_object.services]:
                        continue

                    new_service = add_service(net_object, cve_item)
                    new_service.vulnerabilities = get_vulnerabilities(host_dict['cve_list'], new_service.cpe)
                '''
                for cve_item in cve_list:


    return netmap


def add_service(net_object, item):
    cpe = item.get('cpe') or item.get('possible_cpe')
    port = item['port']

    service = net_object.add_service()
    service.cpe = cpe
    service.port = port

    return service

def get_vulnerabilities(cve_list, cpe):
    vulns = [{'cve':cve_item.get('cve'), 'source':cve_item.get('source_type')}
             for cve_item in cve_list
             if cpe == cve_item.get('cpe') or cpe == cve_item.get('possible_cpe')]

    return vulns


