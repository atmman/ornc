# coding=utf-8
from netaddr import IPNetwork
from netmap_builder.ext.enum import enum
from netmap_builder.ext.serialization import JsonSerializableObject


from exceptions import LastNetObjectAchieved, BadNetInterfaceId, BadServiceId, HostMustHaveOneInterface
from net_interface import create_preconf_net_interface, NetInterface
from service import create_preconf_service, Service


class NetObjectType(enum):
    host = 'host'
    switch = 'switch'
    router = 'router'


class FilterTable(enum):
    ALL = 0
    INPUT = 1
    FORWARD = 2
    OUTPUT = 3


class FilterAction(enum):
    ACCEPT = 0
    DENY = 1
    #  LOG, REJECT, DROP


MAX_NET_OBJECT_ID = 254


def _get_free_net_obj_id(subnet):
    net_obj_ids = [net_obj.id for net_obj in subnet.net_objects]
    for i in xrange(1, MAX_NET_OBJECT_ID + 1):
        if not i in net_obj_ids:
            return i
    raise LastNetObjectAchieved


def create_preconf_net_object(net_obj_type=None, subnet=None, is_filter=False):
    if subnet:
        net_object = NetObject(net_obj_type=net_obj_type, subnet=subnet)
        net_obj_id = _get_free_net_obj_id(subnet)
        if net_obj_id == MAX_NET_OBJECT_ID:
            raise LastNetObjectAchieved
        net_object.id = net_obj_id
    else:
        net_object = NetObject(net_obj_type=net_obj_type)

    if is_filter:
        net_object.is_filter = True

    if net_obj_type == NetObjectType.host:
        net_object.add_net_interface()
        if is_filter:
            net_object.iptable_INPUT = []
            net_object.iptable_OUTPUT = []
    elif net_obj_type == NetObjectType.switch:
        for i in range(4):
            net_object.add_net_interface()
        if is_filter:
            net_object.iptable_FORWARD = []
    elif net_obj_type == NetObjectType.router:
        for i in range(4):
            net_object.add_net_interface()
            net_object.routing_table = []
        if is_filter:
            net_object.iptable_INPUT = []
            net_object.iptable_OUTPUT = []
            net_object.iptable_FORWARD = []

    return net_object


class NetObject(JsonSerializableObject):
    direct_edit_params = ['left', 'top', 'name', 'is_filter']

    def __init__(self, net_obj_type=None, name=None, subnet=None, is_filter=False, left=None, top=None):
        self.id = None
        self.left = left
        self.top = top
        self.type = net_obj_type
        self.name = name
        self.subnet = subnet
        self.is_filter = is_filter
        self.interfaces = []
        self.services = []

        self.raw_filter_rules = None
        self.raw_routing_rules = None
        self.routing_table = None

        self.iptable_INPUT = []
        self.iptable_OUTPUT = []
        self.iptable_FORWARD = []

    def table_pass_packet(self, src_obj, dst_obj, src_service, dst_service):

        def check_table(table, src_networks, dst_networks):
            for src_network in src_networks:
                for dst_network in dst_networks:
                    for row in table:

                        def check_row():
                            dst_service_port = dst_service.port if dst_service else None
                            src_service_port = src_service.port if src_service else None
                            return (
                                src_network.ip in row['src_net'] and dst_network.ip in row['dst_net']
                                and (dst_service_port == row['dst_port'] or not row['dst_port'])
                                and (src_service_port == row['src_port'] or not row['src_port'])
                            )

                        if check_row():
                            if row['action'] == FilterAction.DENY:
                                return False
                            elif row['action'] == FilterAction.ACCEPT:
                                return True
            #  default policy, this is True
            return True

        src_networks = [x.cidr for x in src_obj.interfaces if x.cidr]
        dst_networks = [x.cidr for x in dst_obj.interfaces if x.cidr]

        if not self.is_filter:
            return True

        if self == dst_obj:
            return check_table(self.iptable_INPUT, src_networks, dst_networks)
        elif self == src_obj:
            return check_table(self.iptable_OUTPUT, src_networks, dst_networks)
        elif hasattr(self, 'iptable_FORWARD'):
            return check_table(self.iptable_FORWARD, src_networks, dst_networks)

    #TODO: delete this function
    def add_filter_rule(self, src='0.0.0.0/0', src_port=None, dst='0.0.0.0/0', dst_port=None,
                        action=FilterAction.ACCEPT, table_type=FilterTable.ALL):
        if not self.is_filter:
            self.is_filter = True

        rule = {'src_net': IPNetwork(src), 'src_port': src_port, 'dst_net': IPNetwork(dst), 'dst_port': dst_port,
                'action': action}

        if self.type == NetObjectType.host:
            if table_type == FilterTable.INPUT or table_type == FilterTable.ALL:
                self.iptable_INPUT.append(rule)
            if table_type == FilterTable.OUTPUT or table_type == FilterTable.ALL:
                self.iptable_OUTPUT.append(rule)

        elif self.type == NetObjectType.switch:
            self.iptable_FORWARD.append(rule)

        elif self.type == NetObjectType.router:
            if table_type == FilterTable.INPUT or table_type == FilterTable.ALL:
                self.iptable_INPUT.append(rule)
            if table_type == FilterTable.OUTPUT or table_type == FilterTable.ALL:
                self.iptable_OUTPUT.append(rule)
            if table_type == FilterTable.FORWARD or table_type == FilterTable.ALL:
                self.iptable_FORWARD.append(rule)

    def set_filter_table(self, raw_filter_rules):

        def parse_raw_filter_rules(raw_filter_rules):
            INPUT = []
            OUTPUT = []
            FORWARD = []
            for line in raw_filter_rules.split('\n'):
                params = line.split()

                rule = {}

                #учесть ошибки валидации данных

                try:
                    pos = params.index('-s')
                    rule['src_net'] = IPNetwork(params[pos + 1])
                except ValueError:
                    rule['src_net'] = IPNetwork('0.0.0.0/0')

                try:
                    pos = params.index('-d')
                    rule['dst_net'] = IPNetwork(params[pos + 1])
                except ValueError:
                    rule['dst_net'] = IPNetwork('0.0.0.0/0')

                try:
                    pos = params.index('-sport')
                    rule['src_port'] = int(params[pos + 1])
                except ValueError:
                    rule['src_port'] = None

                try:
                    pos = params.index('-dport')
                    rule['dst_port'] = int(params[pos + 1])
                except ValueError:
                    rule['dst_port'] = None

                if 'ACCEPT' in params:
                    rule['action'] = FilterAction.ACCEPT
                elif 'DENY' in params or 'REJECT' in params:
                    rule['action'] = FilterAction.DENY
                else:
                    continue

                if 'INPUT' in params:
                    INPUT.append(rule)
                elif 'OUTPUT' in line:
                    OUTPUT.append(rule)
                elif 'FORWARD' in line:
                    FORWARD.append(rule)

            return INPUT, OUTPUT, FORWARD

        if not raw_filter_rules:
            return

        INPUT, OUTPUT, FORWARD = parse_raw_filter_rules(raw_filter_rules)

        if self.type == NetObjectType.host:
            FORWARD = []
        elif self.type == NetObjectType.switch:
            INPUT = []
            OUTPUT = []

        self.iptable_INPUT = INPUT
        self.iptable_OUTPUT = OUTPUT
        self.iptable_FORWARD = FORWARD

        self.raw_filter_rules = raw_filter_rules

    def set_routing_table(self, raw_routing_rules):

        def parse_raw_routing_rules(raw_routing_rules):
            rulses = []
            for line in raw_routing_rules.split('\n'):
                params = line.split()

                rule = {}

                #учесть ошибки валидации данных

                try:
                    pos = params.index('-n')
                    rule['network'] = IPNetwork(params[pos + 1])
                except ValueError:
                    raise  # Validation error

                try:
                    pos = params.index('-g')
                    rule['gateway'] = IPNetwork(params[pos + 1])
                except ValueError:
                    raise  # Validation error

                rulses.append(rule)

            return rulses

        self.raw_routing_rules = raw_routing_rules

        if not raw_routing_rules:
            return

        self.routing_table = parse_raw_routing_rules(raw_routing_rules)
        self.raw_routing_rules = raw_routing_rules

    def next_hope_address(self, dst_net_obj):

        """
        If netmask of dst_net_obj in route table pass packet

        @param dst_net_obj:
        @return gateway address:
        """
        dst_network = dst_net_obj.interfaces[0].cidr
        for row in self.routing_table:
            #remove it after Leonid watch
            #dst_network.prefixlen = row['network'].prefixlen
            #if dst_network.network == row['network'].network:

            if dst_network.ip in row['network']:
                for iface in [x for x in self.interfaces if x.cidr]:
                    if iface.cidr.ip in row['gateway']:
                        return row['gateway']

    def get_net_interface(self, net_interface_id):
        filtered = filter(lambda x: x.id == net_interface_id, self.interfaces)
        if not len(filtered):
            raise BadNetInterfaceId
        return filtered[0]

    def get_service(self, service_id):
        filtered = filter(lambda x: x.id == service_id, self.services)
        if not len(filtered):
            raise BadServiceId
        return filtered[0]

    def add_net_interface(self):
        if self.type == NetObjectType.host and len(self.interfaces) == 1:
            raise HostMustHaveOneInterface

        net_interface = create_preconf_net_interface(self)
        self.interfaces.append(net_interface)
        return net_interface

    def add_service(self, type=None, name=None, port=None, db_id=None, interface=None):
        service = create_preconf_service(self, type, name, port, db_id, interface)
        self.services.append(service)
        return service

    def _unlink_interface(self, interface):
        if interface:
            linked = interface.get_linked()
            if linked:
                linked.unlink()
                interface.unlink()
                return linked, interface

    def remove_net_interface(self, interface_id):
        interface = self.get_net_interface(interface_id)
        self._unlink_interface(interface)
        del interface

    def remove_service(self, service_id):
        service = self.get_service(service_id)
        self.services.remove(service)

    def get_free_interface(self):
        for interface in self.interfaces:
            if not interface.is_linked():
                return interface

    def connect(self, net_object_to):
        interface1 = self.get_free_interface()
        interface2 = net_object_to.get_free_interface()

        if not interface1:
            interface1 = self.add_net_interface()
        if not interface2:
            interface2 = net_object_to.add_net_interface()

        interface1.link_with_interface(interface2)

        return interface1, interface2

    def _search_interface_connected(self, net_object_to):
        for interface in self.interfaces:
            if interface.is_linked():
                if interface.get_linked().net_object == net_object_to:
                    return interface
        return None

    def disconnect(self, net_object_to):
        interface = self._search_interface_connected(net_object_to)
        if interface:
            return self._unlink_interface(interface)

    def disconnect_all(self):
        for interface in self.interfaces:
            self._unlink_interface(interface)

    def parse_dict(self, name, value):
        if name == 'interfaces':
            return NetInterface().from_dict(value)
        if name == 'services':
            return Service().from_dict(value)
        if name == 'routing_table':
            return {
                'network': IPNetwork(value['network']),
                'gateway': IPNetwork(value['gateway'])
            } if value else []
        return value

    def serialize_value(self, name, value):
        from subnet import SubNet
        if isinstance(value, SubNet):
            return value.id
        if isinstance(value, IPNetwork):
            return str(value)
        return super(NetObject, self).serialize_value(name, value)

    def __eq__(self, other):
        return self.subnet == other.subnet and self.id == other.id

    def __hash__(self):
        return hash((self.id, self.subnet.id))

    def __unicode__(self):
        return (u'%s %d %s' % (self.name if self.name else self.type, self.id,
                               ', '.join([str(ifc.cidr) for ifc in self.interfaces]))).strip()

    def __str__(self):
        return unicode(self).encode('utf-8')

    __repr__ = __str__