from lxml import etree
from io import BytesIO
from svdb.vuln.db_reader import DB

class ReportParser():

    __xpath_name = etree.XPath("child::nvt/child::name")
    __xpath_host = etree.XPath("child::host")
    __xpath_description = etree.XPath("child::description")
    __xpath_cve = etree.XPath("child::nvt/child::cve")
    __xpath_port = etree.XPath("child::port")

    def __init__(self):
        pass

    def parse_report(self, report):
        '''
        This function return dictionary.
        Output data structure:
        {'host': {'cve_list': [{'cve': '...', 
                                'cve_description': '...', 
                                'service_name': '...', 
                                'port': '...', 
                                'protocol': '...',
                                'cpe': '...'
                                'possible_cpe': [...],
                                'source_type': '...'},...]
                  'cpe_list': [{'cpe': '...', 
                                'port': '...'},...]
                 },...,
        }
        '''
        result_elements = etree.iterparse(BytesIO(report.encode('utf-8')), tag="result")

        parsed_report_dict = dict()
    
        for event, result in result_elements:
            try:
                name = self.__xpath_name(result)[0].text
            except:
                continue
            
            if name == "CPE detection":
                host = self.__xpath_host(result)[0].text
                description = self.__xpath_description(result)[0].text #description field contain cpe lines
                for line in description.splitlines():
                    try:
                        splited_line = line.split('|')[1] #cpe line format: 'ip-address|cpeid#port', example: '192.168.1.1|cpe:/a:nginx:nginx:0.7.67#80' 
                                                          #splited_line = 'cpe:/a:nginx:nginx:0.7.67#80' 
                        cpe = splited_line.split('#')     #cpe = ['cpe:/a:nginx:nginx:0.7.67', '80']
                        if len(cpe) < 2:
                            cpe.append(None)
                    except IndexError:
                        break
                    
                    try:
                        parsed_report_dict[host]['cpe_list'].append({'cpe': cpe[0], 
                                                                     'port': cpe[1]})
                    except:
                        parsed_report_dict[host] = dict(cpe_list=list(), 
                                                        cve_list=list())
                        parsed_report_dict[host]['cpe_list'].append({'cpe': cpe[0], 
                                                                     'port': cpe[1]})
                        
            else:
                cve_str = self.__xpath_cve(result)[0].text
                if cve_str != "NOCVE" and cve_str != None:
                    host = self.__xpath_host(result)[0].text
                    service = self.__xpath_port(result)[0].text.split(' ') #service line format before split: 'service_name (port/protocol)' or 'port/protocol', 
                                                                           #examples: 'ssh (21/tcp)', 'general/icmp'
                                                                           #after spliting: service = ['ssh', '(21/tcp)'] or service = ['general/icmp']
                    cves = cve_str.split(', ')
                    
                    if len(service) > 1:                    #like first examlpe
                        service_name = service[0]
                        port = service[1].split('/')[0][1:]
                        protocol = service[1].split('/')[1][:-1]
                    else:                                   #like second examlpe
                        service_name = None
                        port = service[0].split('/')[0]
                        protocol = service[0].split('/')[1]
                    
                    for cve in cves:
                        try:
                            parsed_report_dict[host]['cve_list'].append({'cve': cve, 
                                                                         'cve_description': name, 
                                                                         'service_name': service_name, 
                                                                         'port': port, 
                                                                         'protocol': protocol, 
                                                                         'cpe': None, 
                                                                         'possible_cpe': None, 
                                                                         'source_type': 'scan'})
                        except:
                            parsed_report_dict[host] = dict(cpe_list=list(), 
                                                            cve_list=list())
                            parsed_report_dict[host]['cve_list'].append({'cve': cve, 
                                                                         'cve_description': name, 
                                                                         'service_name': service_name, 
                                                                         'port': port, 
                                                                         'protocol': protocol, 
                                                                         'cpe': None, 
                                                                         'possible_cpe': None, 
                                                                         'source_type': 'scan'})
            result.clear()
        del result_elements
        
        parsed_report_dict = ReportParser.find_cpe_for_cve(parsed_report_dict)
        parsed_report_dict = ReportParser.append_cve_by_cpe(parsed_report_dict)
        
        return parsed_report_dict

    @classmethod
    def find_cpe_for_cve(cls, parsed_report_dict):
        '''
        '''
        for host, host_dict in parsed_report_dict.items():
            
            for cve in host_dict.get('cve_list'):
                DB.init()
                possible_cpes = DB.get_cpe_by_cve(cve.get('cve'))
                
                for cpe in host_dict.get('cpe_list'):
                    if cve.get('port') != cpe.get('port'):
                        cve['possible_cpe'] = possible_cpes
                        continue
                    
                    try:
                        cpeid = possible_cpes.index(cpe.get('cpe'))
                        cve['cpe'] = cpe.get('cpe')
                        cve['possible_cpe'] = None
                    except:
                        cve['cpe'] = None
                        cve['possible_cpe'] = possible_cpes
                    
        return parsed_report_dict
    
    @classmethod
    def append_cve_by_cpe(cls, parsed_report_dict):
        '''
        '''
        DB.init()
        for host, host_dict in parsed_report_dict.items():
            
            for cpe in host_dict.get('cpe_list'):
                
                for cve_from_db, summary in DB.get_cve_by_cpe(cpe.get('cpe')):
                    is_in_list = False
                    for cve in host_dict.get('cve_list'):
                        if cve_from_db == cve.get('cve'):
                            is_in_list = True
                            break
                    if not is_in_list:
                        parsed_report_dict[host]['cve_list'].append({'cve': cve_from_db, 
                                                                    'cve_description': summary, 
                                                                    'service_name': None, 
                                                                    'port': cpe.get('port'), 
                                                                    'protocol': None, 
                                                                    'cpe': cpe.get('cpe'), 
                                                                    'possible_cpe': None, 
                                                                    'source_type': 'db'})
  
        return parsed_report_dict
