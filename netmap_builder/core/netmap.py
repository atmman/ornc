# coding=utf-8
from filter_rule import FilterRule
from service import Service
from exceptions import BadFilterRuleId, BadNetMapId, LastNetMapAchieved, BadSubNetId
from subnet import SubNet
from netmap_builder.ext.serialization import JsonSerializableObject
from net_object import NetObject


MAX_NET_MAP_ID = 254

_net_maps = {}


def get_netmap_by_id(net_map_id):
    if net_map_id in _net_maps:
        return _net_maps[net_map_id]
    raise BadNetMapId()


def cache_net_map(net_map):
    _net_maps[net_map.id] = net_map


def create_preconf_net_map(name):
    net_map = NetMap(name)

    net_map_id = _get_free_net_map_id()
    if net_map_id == MAX_NET_MAP_ID:
        raise LastNetMapAchieved
    net_map.id = net_map_id

    return net_map


def _get_free_net_map_id():
    for i in xrange(1, MAX_NET_MAP_ID + 1):
        if not i in _net_maps:
            return i
    raise LastNetMapAchieved


class NetMap(JsonSerializableObject):
    __serializable_fields = ['id', 'subnets', 'width', 'height']

    def __init__(self, name="", width=1000, height=700):
        self.id = None
        self.name = name

        self.width = width
        self.height = height

        self.subnets = []

        subnet = SubNet(net_map=self, name="routers_subnet")
        subnet.id = 0
        self.subnets.append(subnet)
        self.routers = self.subnets[0].net_objects

        self.required_access_rules = []

    def add_router(self, router):
        router.id = self.routers[-1].id + 1 if self.routers else 2 ** 31
        self.routers.append(router)

    def get_router(self, router_id):
        filtered = filter(lambda x: x.id == router_id, self.routers)
        if not len(filtered):
            raise BadSubNetId
        return filtered[0]

    def remove_router(self, router_id):
        router = self.get_router(router_id)
        router.disconnect_all()
        self.routers.remove(router)

    def parse_dict(self, name, value):
        if name == 'subnets':
            return SubNet().from_dict(value)
        return value

    def get_subnet(self, subnet_id):
        filtered = filter(lambda x: x.id == subnet_id, self.subnets)
        if not len(filtered):
            raise BadFilterRuleId
        return filtered[0]

    def add_subnet(self):
        subnet = SubNet(self)
        self.subnets.append(subnet)
        return subnet

    def remove_subnet(self, subnet_id):
        subnet = self.get_subnet(subnet_id)
        for net_object in subnet.net_objects:
            subnet.remove_net_object(net_object.id)

        self.subnets.remove(subnet)

# required_access_rules

    def add_required_access_rule_old(self, entity_from, entity_to, access_type):
        rule = {'entity_from': entity_from, 'entity_to': entity_to, 'access_type': access_type}
        self.required_access_rules.append(rule)
        return len(self.required_access_rules) - 1

    def add_required_access_rule(self, rule_dict=None):
        rule = FilterRule(**rule_dict)
        self.required_access_rules.append(rule)

        return rule

    def get_required_access_rule_old(self, rule_id):

        def ret_ids(object):
            if isinstance(object, Service):
                return object.id, object.net_object.id, object.net_object.subnet.id
            elif isinstance(object, NetObject):
                return object.id, object.subnet.id, None
            elif isinstance(object, SubNet):
                return object.id, None, None

        rule = self.required_access_rules[rule_id]

        entity_from = rule['entity_from']
        entity_to = rule['entity_to']
        access_type = rule['access_type']

        src_subnet_id, src_net_object_id, src_service_id = ret_ids(entity_from)
        dst_subnet_id, dst_net_object_id, dst_service_id = ret_ids(entity_to)
        access_type = access_type

        ret_rule = {'src_subnet_id': src_subnet_id, 'src_net_object_id': src_net_object_id,
                    'src_service_id': src_service_id, 'dst_subnet_id': dst_subnet_id,
                    'dst_net_object_id': dst_net_object_id, 'dst_service_id': dst_service_id,
                    'access_type': access_type}

        return ret_rule

    def get_required_access_rule(self, rule_id):
        filtered = filter(lambda x: x.id == rule_id, self.required_access_rules)
        if not len(filtered):
            raise BadFilterRuleId
        return filtered[0]

    def get_required_access_rules(self):

        rules_list = [x for x in self.required_access_rules]
        return rules_list

    def remove_required_access_rule(self, rule_id):
        del self.required_access_rules[rule_id]

    def update_required_access_rule(self, rule_id, data=None):
        rule = self.get_required_access_rule(rule_id)

    def clear(self):
        pass

    def __eq__(self, other):
        return self.id == other.id