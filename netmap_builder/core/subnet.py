# coding=utf-8
from netaddr import IPNetwork

from exceptions import BadNetObjectId, LastSubNetAchieved
from net_object import NetObject
from netmap_builder.ext.serialization import JsonSerializableObject


MAX_SUBNET_ID = 254


def _get_free_net_id(net_map):
    subnets_id = [subnet.id for subnet in net_map.subnets]
    for i in xrange(1, MAX_SUBNET_ID + 1):
        if not i in subnets_id:
            return i
    raise LastSubNetAchieved


def generate_cidr(subnet):
    cidr_str = "10.%s.%s.0/24" % (subnet.net_map.id, subnet.id)
    return IPNetwork(cidr_str)


def create_preconf_subnet(net_map=None):
    subnet = SubNet(net_map=net_map)

    subnet_id = _get_free_net_id(net_map)
    if subnet_id == MAX_SUBNET_ID:
        raise LastSubNetAchieved
    subnet.id = subnet_id

    subnet.cidr = generate_cidr(subnet)
    return subnet


class SubNet(JsonSerializableObject):
    direct_edit_params = ['left', 'top', 'width', 'height', 'name', 'cidr']

    def __init__(self, net_map=None, cidr=None, name='', left=None, top=None, width=500, height=300):
        self.id = None
        self.left = left
        self.top = top

        self.width = width
        self.height = height

        self.name = name
        self.cidr = cidr

        self.net_map = net_map
        self.net_objects = []

    def get_net_object(self, net_object_id):
        filtered = filter(lambda x: x.id == net_object_id, self.net_objects)
        if not len(filtered):
            raise BadNetObjectId
        return filtered[0]

    def add_net_object(self):
        net_object = NetObject()
        self.net_objects.append(net_object)
        return net_object

    def remove_net_object(self, net_object_id):
        net_object = self.get_net_object(net_object_id)
        net_object.disconnect_all()
        self.net_objects.remove(net_object)

    def parse_dict(self, name, value):
        if name == 'cidr':
            if isinstance(value, IPNetwork):
                return value
            elif value is None:
                return None
            return IPNetwork(value)
        elif name == 'net_objects':
            return NetObject().from_dict(value)
        return value

    def serialize_value(self, name, value):
        from netmap import NetMap
        if isinstance(value, IPNetwork):
            return str(value)
        elif isinstance(value, NetMap):
            return value.id
        else:
            return super(SubNet, self).serialize_value(name, value)

    def __eq__(self, other):
        return self.net_map == other.net_map and self.id == other.id

    def __hash__(self):
        return hash((self.id, ))

    def __unicode__(self):
        return (u'%s' % self.name).strip()

    def __str__(self):
        return unicode(self).encode('utf-8')

    __repr__ = __str__
