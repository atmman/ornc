# coding=utf-8
from services_db import ServiceDatabaseManager
from vulnerability import Vulnerability
from exceptions import LastServiceAchieved
from netmap_builder.ext.serialization import JsonSerializableObject


MAX_SERVICES_ID = 65000


def _get_free_service_id(net_object):
    services_ids = [service.id for service in net_object.services]
    for i in xrange(1, MAX_SERVICES_ID + 1):
        if not i in services_ids:
            return i
    raise LastServiceAchieved


def create_preconf_service(net_object, type, name, port, db_id, interface):
    service = Service(net_object, type, name, port, db_id, interface)
    service_id = _get_free_service_id(net_object)
    if service_id == MAX_SERVICES_ID:
        raise LastServiceAchieved
    service.id = service_id

    return service


class Service(JsonSerializableObject):

    def __init__(self, net_object=None, type=None, name=None, port=None, db_id=None, interface=None):
        self.id = None
        self.type = type
        self.name = name
        self.port = port
        self.net_object = net_object
        self.interface = interface

        self.cpe = None
        self.vulnerabilities = []

        if db_id:
            with ServiceDatabaseManager() as manager:
                res = manager.get_service_info(db_id)
                self.cpe = res['cpe']
                self.vulnerabilities = res['vulns']

    def vulnerabilities_by_access_type(self, access_type):
        return [vuln for vuln in self.vulnerabilities if vuln.cvss_metrics.access_vector == access_type]

    def parse_dict(self, name, value):
        if name == 'vulnerabilities':
            return Vulnerability().from_dict(value)
        return value

    def serialize_value(self, name, value):
        from net_object import NetObject
        from net_interface import NetInterface
        if isinstance(value, NetObject):
            return value.id
        elif isinstance(value, NetInterface):
            return value.id
        else:
            return super(Service, self).serialize_value(name, value)

    def __unicode__(self):
        res = u"service:: "
        if self.name:
           res += u"name: " + self.name.strip()

        if self.interface:
            res += u"interface: " + self.interface.cidr

        if self.port:
            res += u"port: " + unicode(self.port)

        if self.cpe:
            res += u"cpe: " + self.cpe

        return res

    def __eq__(self, other):
        return self.net_object == other.net_object and self.id == other.id

    def __hash__(self):
        return hash((self.id, self.net_object.id, self.net_object.subnet.id))

    def __str__(self):
        return unicode(self).encode('utf-8')

    __repr__ = __str__