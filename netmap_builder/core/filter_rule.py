# coding=utf-8
import uuid

from net_object import NetObject
from service import Service
from subnet import SubNet

from netmap_builder.ext.serialization import JsonSerializableObject


def gen_id():
    return uuid.uuid4()


class FilterRule(JsonSerializableObject):

    def __init__(self, name=None, netmap=None):
        self.id = None  # gen id
        self.type = None
        self.netmap = netmap
        self.is_active = None
        self.entity_from = None
        self.entity_to = None
        self.access_type = None

        #linked rules
        self.sub_rules = []

    def parse_dict(self, name, value):
        if name == 'src_subnet':
            pass
        if name == 'src_net_object':
            pass
        return value

    def serialize_value(self, name, value):
        if isinstance(value, SubNet):
            return value.id
        elif isinstance(value, NetObject):
            return value.subnet.id, value.id
        elif isinstance(value, Service):
            return value.net_object.subnet.id, value.net_object.id, value.id

        else:
            return super(FilterRule, self).serialize_value(name, value)

    def __eq__(self, other):
        return self.netmap == other.netmap and self.id == other.id

    def __unicode__(self):
        return (u'%s' % self.access_type)

    def __str__(self):
        return unicode(self).encode('utf-8')

    __repr__ = __str__