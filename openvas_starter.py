from openvas_client import OpenvasClient
from report_parser import ReportParser
import time, os, sys


class CONFIG_TYPES(object):
    full_n_fast = 'Full and fast'
    full_n_fast_ult = 'Full and fast ultimate'
    full_n_deep = 'Full and very deep'
    full_n_deep_ult = 'Full and very deep ultimate'
    
    
class PORT_LIST_TYPE(object):
    default = 'OpenVAS Default'
    all_tcp = 'All TCP'    
    all_tcp_n_top100_nmap = 'All TCP and Nmap 5.51 top 100 UDP'
    all_tcp_n_top1000_nmap = 'All TCP and Nmap 5.51 top 1000 UDP'
    all_privileged_tcp = 'All privileged TCP'
    all_privileged_tcp_n_udp = 'All privileged TCP and UDP'
    
    
class ParamError(Exception):
    def __init__(self, value):
        self.value = value


def start_task(parameters):
    '''
    parameters = {
                  'manager_host': '...',
                  'manager_port': '...',
                  'user': '...',
                  'password': '...',
                  'task_name': '...',
                  'targets': '...',
                  'port_list': '...',
                  'config_type': '...'
                  'progress_callback': func
                  'error_callback': func
                  'success_callback': func
                 }
    '''
    if type(parameters) != type(dict()):
        sys.exit()
        
    #Manager host
    manager_host = parameters.get('manager_host') or '127.0.0.1'
    print "OpenVAS Manager's host: %s" % manager_host
    
    #Manager port
    manager_port = parameters.get('manager_port')
    
    #Manager user 
    user = parameters.get('user')
    if user == None:
        print 'Error: None user parameter'
        sys.exit()
    
    #Task and target name
    task_name = parameters.get('task_name')
    if task_name == None:
        date = time.localtime()
        date_name = '%i%i%i_%i%i' % (date[2], date[1], date[0], date[3], date[4])
        task_name = 'task_' + date_name
        target_name = task_name + '_target'
        print "Task name: %s\nTarget name: %s" % (task_name, target_name)
    else:
        target_name = task_name + '_target'
        print "Task name: %s\nTarget name: %s" % (task_name, target_name)
    
    #Task targets
    targets = parameters.get('targets')
    if targets == None:
        print 'Error: None task target parameter'
        sys.exit()

    #Task target port list    
    port_list = parameters.get('port_list') or PORT_LIST_TYPE.default
    print 'Target port list: %s' % port_list
    
    #Scan configuration
    config_type = parameters.get('config_type')
    if config_type == None:
        print 'Error: None scan configuretion type parameter'
        sys.exit()
    print 'Scan config: %s' % config_type

    #Callback functions
    on_success = parameters.get('success_callback')
    if not on_success:
        print 'Error: None success callback-function parameter'
        sys.exit()
    on_error = parameters.get('error_callback')
    on_progress = parameters.get('progress_callback')

    manager = OpenvasClient(host=manager_host, port=manager_port)
    manager.open_session(user)
    port_lists = manager.get_port_lists()
    port_list_id = port_lists[port_list]

    new_target_id = manager.create_target(target_name, targets, port_list_id)
    configs = manager.get_configs()

    new_task_id = manager.create_task(task_name, configs[config_type], new_target_id)

    manager.start_task(new_task_id)

    manager.wait_task(new_task_id, on_success, on_error, on_progress)


def on_error_test(error):
    print error


def on_progress_test(progress):
    print '%s%%' % progress

    
def on_success_test(manager, report_id):
    report = manager.get_report_xml(report_id)
    
    parser = ReportParser()
    report = parser.parse_report(report)
    
    report = ReportParser.find_cpe_for_cve(report)
    report = ReportParser.append_cve_by_cpe(report)
    
    print report


if __name__ == '__main__':
#TODO: test it!!
    test_param = {
                    'manager_host': '10.10.133.227',
                    'user' : ('test_admin', 'admin'),
                    'targets': '10.10.133.1',
                    'config_type': CONFIG_TYPES.full_n_fast,
                    'success_callback': on_success_test()
                 }
    
    start_task(test_param)
