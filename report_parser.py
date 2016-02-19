from lxml import etree
from io import BytesIO
from svdb.vuln.db_reader import DB

xpath_test_name = etree.XPath("child::nvt/child::name")
xpath_host = etree.XPath("child::host")
xpath_description = etree.XPath("child::description")
xpath_cve = etree.XPath("child::nvt/child::cve")
xpath_service = etree.XPath("child::port")


def exec_xpath_query(xpath, xml):
    result = xpath(xml)[0].text
    return result


class _service():
    def __init__(self, raw_service_line):

        service = raw_service_line.split(' ')
        service.reverse()

        self.port = service[0].split('/')[0].strip('(')
        self.protocol = service[0].split('/')[1].strip(')')

        if len(service) > 1:
            self.service_name = service[-1]
        else:
            self.service_name = None


class _cpe_id():
    def __init__(self, raw_cpe_line):
        from svdb.id.cpe import CPEID
        cpe_n_port = raw_cpe_line.split('|')[1].split('#')
        if CPEID.correct_cpe_str(cpe_n_port[0]):
            self.cpe = cpe_n_port[0]
        try:
            self.port = cpe_n_port[1]
            if self.port is '':
                self.port = None
        except:
            self.port = None


class ReportParser():

    def add_cpe_list(self, parsed_report_dict, result_item):
        host = exec_xpath_query(xpath_host, result_item)

        row_cpe_str = exec_xpath_query(xpath_description, result_item)
        row_cpe_list = row_cpe_str.strip().splitlines()
        for cpe_item in row_cpe_list:
            cpe_obj = _cpe_id(cpe_item)

            if not parsed_report_dict.get(host):
                parsed_report_dict[host] = dict(cpe_list=list(), cve_list=list())

            parsed_report_dict[host]['cpe_list'].append({'cpe': cpe_obj.cpe, 'port': cpe_obj.port})
        return parsed_report_dict

    def add_cve_list(self, parsed_report_dict, row_cve_str, result_item, result_item_name):
        host = exec_xpath_query(xpath_host, result_item)
        cve_list = [cve.strip(',') for cve in row_cve_str.split()]
        raw_service = exec_xpath_query(xpath_service, result_item)
        service = _service(raw_service)
        for cve in cve_list:
            if not parsed_report_dict.get(host):
                parsed_report_dict[host] = dict(cpe_list=list(), cve_list=list())
            parsed_report_dict[host]['cve_list'].append({'cve': cve,
                                                         'cve_description': result_item_name,
                                                         'service_name': service.service_name,
                                                         'port': service.port,
                                                         'protocol': service.protocol,
                                                         'cpe': None,
                                                         'possible_cpe': None,
                                                         'source_type': 'scan'})
        return parsed_report_dict

    def find_cpe_for_cve(self, parsed_report_dict):
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

    def append_cve_by_cpe(self, parsed_report_dict):
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

        cpe_detection_test = "CPE detection"
        nocve = "NOCVE"

        result_elements = etree.iterparse(BytesIO(report.encode('utf-8')), tag="result")

        parsed_report_dict = dict()
    
        for event, result_item in result_elements:

            result_item_name = exec_xpath_query(xpath_test_name, result_item)

            if result_item_name == cpe_detection_test:
                self.add_cpe_list(parsed_report_dict, result_item)

            else:
                row_cve_str = exec_xpath_query(xpath_cve, result_item)

                if row_cve_str != nocve and row_cve_str != None:
                    self.add_cve_list(parsed_report_dict, row_cve_str, result_item, result_item_name)#kill unusable elements

            result_item.clear()
        del result_elements
        
        self.find_cpe_for_cve(parsed_report_dict)
        self.append_cve_by_cpe(parsed_report_dict)
        
        return parsed_report_dict
