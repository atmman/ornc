from lxml import etree
from io import BytesIO
from svdb.vuln.db_reader import DB

xpath_test_name = etree.XPath("child::nvt/child::name")
xpath_host = etree.XPath("child::host")
xpath_description = etree.XPath("child::description")
xpath_cve = etree.XPath("child::nvt/child::cve")
xpath_port = etree.XPath("child::port")

def exec_xpath_query(xpath, xml):
    result = xpath(xml)[0].text
    return result

class ReportParser():


    __xpath_description = etree.XPath("child::description")
    __xpath_cve = etree.XPath("child::nvt/child::cve")
    __xpath_port = etree.XPath("child::port")

    class _openvas_cpe_id():
        def __init__(self, raw_cpe_line):

            __cpe_n_port = raw_cpe_line.split('|')[1].split('#')
            self.cpe = __cpe_n_port[0]
            try:
                self.port = __cpe_n_port[1]
            except:
                self.port = None


    def parse_report(self, report):
        cpe_detection_test = "CPE detection"
        nocve = "NOCVE"

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
    
        for event, test in result_elements:
            host = exec_xpath_query(xpath_host, test)
            test_name = exec_xpath_query(xpath_test_name, test)

            if test_name == cpe_detection_test:
                row_cpe_str = exec_xpath_query(xpath_description, test)
                row_cpe_list = row_cpe_str.strip().splitlines()

                for cpe_item in row_cpe_list:
                    cpe_obj = self._openvas_cpe_id(cpe_item)

                    if not parsed_report_dict.get(host):
                        parsed_report_dict[host] = dict(cpe_list=list(), cve_list=list())

                    parsed_report_dict[host]['cpe_list'].append({'cpe': cpe_obj.cpe, 'port': cpe_obj.port})

            else:
                cve_str = self.__xpath_cve(test)[0].text
                if cve_str != nocve and cve_str != None:

                    service = self.__xpath_port(test)[0].text.split(' ') #service line format before split: 'service_name (port/protocol)' or 'port/protocol',
                                                                           #examples: 'ssh (21/tcp)', 'general/icmp'
                                                                           #after spliting: service = ['ssh', '(21/tcp)'] or service = ['general/icmp']
                    cves = cve_str.split(', ')
                    print cve_str.split()
                    
                    if len(service) > 1:                    #like first examlpe
                        service_name = service[0]
                        port = service[1].split('/')[0][1:]
                        protocol = service[1].split('/')[1][:-1]
                    else:                                   #like second examlpe
                        service_name = None
                        port = service[0].split('/')[0]
                        protocol = service[0].split('/')[1]

                    for cve in cves:
                        if not parsed_report_dict.get(host):
                            parsed_report_dict[host] = dict(cpe_list=list(), cve_list=list())
                        parsed_report_dict[host]['cve_list'].append({'cve': cve,
                                                                     'cve_description': test_name,
                                                                     'service_name': service_name,
                                                                     'port': port,
                                                                     'protocol': protocol,
                                                                     'cpe': None,
                                                                     'possible_cpe': None,
                                                                     'source_type': 'scan'})
            test.clear()
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
