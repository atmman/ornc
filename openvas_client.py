import socket, ssl, time
from lxml import etree
from lxml.builder import E
from io import BytesIO


class StatusError(Exception):
    pass


class OpenvasClient():

    __MANAGER_DEFAULT_PORT = 9390
    __TASK_FINISHED = '-1'
    RECV_BLOCK_SIZE = 1024
    
    def __init__(self, host, port=None, user=None, passwd=None):
        self.__s = None
        self.__host = host
        if port != None:
            self.__port = port
        else:
            self.__port = self.__MANAGER_DEFAULT_PORT
        self.__user = user
        self.__passwd = passwd
        self.__last_query = str()

    def open_session(self, (user, passwd)):
        self.__s = ssl.wrap_socket(socket.socket())
        self.__s.connect((self.__host, self.__port))

        self.__auth(user, passwd)

    def __auth(self, user=None, passwd=None):       
        if user == None: 
            user = self.__user
        if passwd == None:
            passwd = self.__passwd

        self.__last_query = E.authenticate( E.credentials ( E.username(user),
                                                            E.password(passwd) ))
        self.__make_query()

    def create_target(self, name, hosts, port_list_id=None, comment=str()):

        if port_list_id == None:
            self.__last_query = E.create_target( E.name(name),
                                                 E.hosts(hosts),
                                                 E.comment(comment))
        else:
            self.__last_query = E.create_target( E.name(name),
                                                 E.hosts(hosts),
                                                 E.comment(comment),
                                                 E.port_list(id=port_list_id))
        
        created_target_id = self.__make_create_query()
        return created_target_id
    
    def create_task(self, name, config_id, target_id, comment=str()):
        self.__last_query = E.create_task( E.name(name),
                                           E.comment(comment),
                                           E.config(id=config_id),
                                           E.target(id=target_id))
        
        created_task_id = self.__make_create_query()
        return created_task_id

    def get_configs(self):
        self.__last_query = E.get_configs(preferences='0', families='0')

        configs_dict = self.__make_get_query(type = 'config')
        return configs_dict

    def get_tasks(self, task_id=None):       
        if task_id == None:
            self.__last_query = E.get_tasks()
        else:
            self.__last_query = E.get_tasks(task_id=task_id)
        
        tasks_dict = self.__make_get_query(type = 'task')
        return tasks_dict

    def get_port_lists(self):
        self.__last_query = E.get_port_lists(details='0', targets='0')

        port_lists_dict = self.__make_get_query('port_list')
        return port_lists_dict
           
    def get_report_xml(self, report_id):
        self.__last_query = E.get_reports(report_id=report_id)
        
        response = self.__make_query()
        return response

    def start_task(self, task_id):
        self.__last_query = E.start_task(task_id=task_id)
        self.__make_query()

    def wait_task(self, task_id, on_success, on_error=None, on_progress=None, sleep_time=10):
        while True:
            try:
                progress, report_id = self.get_tasks(task_id)[task_id]
            except StatusError as er:
                if on_error:
                    on_error(er.value)
                    break
                
            if progress == self.__TASK_FINISHED:
                on_success(self, report_id)
                break
            else:
                if on_progress:
                    on_progress(progress)
                time.sleep(sleep_time)
                
    def __send_recv(self, request):
        response = ''
        self.__s.send(request)
        while 1:
            r = self.__s.recv(self.RECV_BLOCK_SIZE)
            response = response + r
            if len(r) < self.RECV_BLOCK_SIZE:
                break
        return response
    
    def __check_status(self, response):
        response = etree.fromstring(response)
        
        status = response.get("status")
        status_text = response.get("status_text")
        
        if status == None:
            raise StatusError("None status!")        
        elif status.startswith("4"):
            raise StatusError("%s, %s" % (status, status_text))
        elif status.startswith("5"):
            raise StatusError("%s, %s" % (status, status_text))
    
    def __parse_get_response(self, response, type):       
        response_iter = etree.iterparse(BytesIO(response.encode('utf-8')), tag=type)
        data = dict()
        
        for event, iter in response_iter:
            uuid = iter.get('id')
            name = iter.find('name')
            if type == 'task':
                try:
                    progress = iter.find('progress').find('host_progress').tail
                except:
                    progress = iter.find('progress').text
                
                try:
                    last_report_id_xpath = etree.XPath("last_report/report/@id")
                    last_report_id = last_report_id_xpath(iter)[0]
                    data[uuid] = (progress, last_report_id)
                except:
                    data[uuid] = (progress, '')
            
            else:
                data[name.text] = uuid
            
            iter.clear()
        del response_iter
        return data
    
    def __make_query(self, query = None):
        if not query:
            query = self.__last_query
            
        query_tostring = etree.tostring(query)
        response = self.__send_recv(query_tostring)
        self.__check_status(response)
        
        return response
    
    def __make_create_query(self, query = None):
        response = self.__make_query()
        created_obj_id = etree.fromstring(response).get("id")
        
        return created_obj_id
    
    def __make_get_query(self, type, query = None):
        response = self.__make_query()
        dict_from_response = self.__parse_get_response(response, type)
        
        return dict_from_response
