# coding=utf-8
from netaddr import IPNetwork

from exceptions import AlreadyLinked, LastNetInterfaceAchieved, ErrorSetCidr, ErrorSetGateway
from netmap_builder.ext.serialization import JsonSerializableObject


MAX_NET_INTERFACES_ID = 254


def _get_free_net_id(net_object):
    net_interface_ids = [net_interface.id for net_interface in net_object.interfaces]
    for i in xrange(1, MAX_NET_INTERFACES_ID + 1):
        if not i in net_interface_ids:
            return i
    raise LastNetInterfaceAchieved


def generate_cidr(net_object):
    from net_object import NetObjectType
    if net_object.type == NetObjectType.host:
        cidr_str = "10.%s.%s.%s/24" % (net_object.subnet.net_map.id, net_object.subnet.id, net_object.id)
        return IPNetwork(cidr_str)


def generate_gateway(net_object):
    from net_object import NetObjectType
    if net_object.type == NetObjectType.host:
        gateway = "10.%s.%s.254/32" % (net_object.subnet.net_map.id, net_object.subnet.id)
        return IPNetwork(gateway)


def create_preconf_net_interface(net_object=None):
    net_interface = NetInterface(net_object=net_object)

    net_interface_id = _get_free_net_id(net_object)
    if net_interface_id == MAX_NET_INTERFACES_ID:
        raise LastNetInterfaceAchieved

    net_interface.id = net_interface_id
    net_interface.cidr = generate_cidr(net_object)
    net_interface.gateway = generate_gateway(net_object)

    return net_interface


class NetInterface(JsonSerializableObject):

    def __init__(self, net_object=None, name=None):
        self.id = None
        self.net_object = net_object
        self.cidr = None
        self.gateway = None
        self.name = name
        self._linked_interface = None

    def set_cidr(self, cidr):
        if isinstance(cidr, IPNetwork):
            self.cidr = cidr
        else:
            try:
                self.cidr = IPNetwork(cidr)
            except:
                raise ErrorSetCidr

    def set_gateway(self, gateway):
        if isinstance(gateway, IPNetwork):
            self.gateway = gateway
        else:
            try:
                self.gateway = IPNetwork(gateway)
            except:
                raise ErrorSetGateway

    def link_with_interface(self, interface):
        if self._linked_interface:
            raise AlreadyLinked
        interface._linked_interface = self
        self._linked_interface = interface

    def link_with_object(self, net_object):
        interface1 = self
        interface2 = net_object.get_free_interface()
        if not interface2:
            interface2 = net_object.add_net_interface()

        interface1.link_with_interface(interface2)

        return interface2

    def unlink(self):
        self._linked_interface = None

    def is_linked(self):
        return self._linked_interface is not None

    def get_linked(self):
        return self._linked_interface

    def serialize_value(self, name, value):
        from net_object import NetObject
        if isinstance(value, NetObject):
            return value.id
        elif isinstance(value, NetInterface):
            return {'subnet_id': value.net_object.subnet.id,
                    'net_object_id': value.net_object.id, 'interface_id': value.id}
        elif isinstance(value, IPNetwork):
            return str(value)
        else:
            return super(NetInterface, self).serialize_value(name, value)

    def parse_dict(self, name, value):
        if name in ('cidr', 'gateway'):
            return IPNetwork(value) if value else None
        return value

    def __eq__(self, other):
        return self.net_object == other.net_object and self.id == other.id

    def __unicode__(self):
        return u'interface (id=%s) (name=%s) (cidr=%s)' % (self.id, self.name, self.cidr)

    def __str__(self):
        return unicode(self).encode('utf-8')

    __repr__ = __str__