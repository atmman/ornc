from netaddr import IPNetwork

def combine_netmap_report(netmap, report_dict):
    for subnet in netmap.subnets:
        for net_object in subnet.net_objects:
            for interface in net_object.interfaces:

                if not interface.cidr:
                    continue
                
                host_dict = report_dict.get(str(interface.cidr.ip))

                for cpe_item in host_dict.get('cpe_list'):
                    cpe = cpe_item['cpe']
                    port = cpe_item.get('port')
                    vulns = get_vulnerabilities(host_dict, cpe)
                    add_service(net_object, cpe, port, vulns)

                for cve_item in host_dict.get('cve_list'):
                    if not cve_item.get('possible_cpe'):
                        continue
                    if cve_item.get('possible_cpe') in [service.cpe for service in net_object.services]:
                        continue
                    cpe = cve_item['possible_cpe']
                    port = cve_item.get('port')
                    vulns = get_vulnerabilities(host_dict, cpe)
                    add_service(net_object, cpe, port, vulns)

    return netmap

def add_service(net_object, cpe, port, vulns):
    service = net_object.add_service()
    service.cpe = cpe
    service.port = port
    service.vulnerabilities = vulns

    return service

def get_vulnerabilities(host_dict, cpe):
    vulns = [{'cve':cve_item.get('cve'), 'source':cve_item.get('source_type')}
             for cve_item in host_dict.get('cve_list')
             if cpe == cve_item.get('cpe') or cpe == cve_item.get('possible_cpe')]

    return vulns