# coding=utf-8
from net_object import NetObjectType


class ReachabilityController(object):

    def __init__(self, net_map, events=None):
        self._net_map = net_map
        self._res_table = None

    def has_access(self, src_obj, dst_obj, src_service=None, dst_service=None):

        def find_not_filtered_hops_in_subnet(net_object):
            switch_list = []
            router_list = []
            hosts_list = []

            passed_list.append(net_object)

            if not net_object.table_pass_packet(src_obj, dst_obj, src_service, dst_service):
                return router_list, hosts_list

            for interface in filter(lambda i: i.is_linked(), net_object.interfaces):

                connected_object = interface.get_linked().net_object
                if connected_object not in passed_list:

                    #Фильтрация
                    if connected_object.table_pass_packet(src_obj, dst_obj, src_service, dst_service):
                        if connected_object.type == NetObjectType.switch:
                            switch_list.append(connected_object)
                        elif connected_object.type == NetObjectType.router:
                            router_list.append(connected_object)
                        elif connected_object.type == NetObjectType.host:
                            hosts_list.append(connected_object)

            for hop in switch_list:
                result = find_not_filtered_hops_in_subnet(hop)
                router_list.extend(result[0])
                hosts_list.extend(result[1])

            return router_list, hosts_list

        def find_router_with_gateway(gateway, routers):
            for router in routers:
                for interface in (x for x in router.interfaces if x.cidr):
                    if gateway.ip == interface.cidr.ip:
                        return router

        #Check to self
        if src_obj is dst_obj:
            #Filtration
            return src_obj.table_pass_packet(src_obj, dst_obj, src_service, dst_service)

        passed_list = []
        obj_list = [src_obj]

        for hop_src_obj in obj_list:
            router_list, hosts_list = find_not_filtered_hops_in_subnet(hop_src_obj)

            if dst_obj in hosts_list + router_list:
                return True

            if hop_src_obj.type == NetObjectType.host:
                router = find_router_with_gateway(hop_src_obj.interfaces[0].gateway, router_list)
                if not router:
                    #  Cannot find next gateway
                    return False

                next_gateway = router.next_hope_address(dst_obj)
                if not next_gateway:
                    #  Router with no route to destination host
                    return False
                obj_list.append(router)

            elif hop_src_obj.type == NetObjectType.router:
                next_gateway = hop_src_obj.next_hope_address(dst_obj)
                if not next_gateway:
                    return False    # Router with no route to destination host

                router = find_router_with_gateway(next_gateway, router_list)
                if not router:
                    return False    # Cannot find next gateway
                obj_list.append(router)

    def calculate(self):

        class NestedDict(dict):
            def __getitem__(self, key):
                if key in self:
                    return self.get(key)
                return self.setdefault(key, NestedDict())

        res_table = NestedDict()

        for src_subnet in self._net_map.subnets:
            for src_net_obj in src_subnet.net_objects:
                if src_net_obj.type == NetObjectType.switch:
                    continue
                for dst_subnet in self._net_map.subnets:
                    for dst_net_obj in dst_subnet.net_objects:
                        if dst_net_obj.type == NetObjectType.switch:
                            continue

                        table_part = res_table[src_subnet.id][src_net_obj.id]

                        #from object to object
                        access = self.has_access(src_net_obj, dst_net_obj)
                        table_part['default'][dst_subnet.id][dst_net_obj.id]['default'] = access

                        #from object to service
                        for dst_service in dst_net_obj.services:
                            access = self.has_access(src_net_obj, dst_net_obj, None, dst_service)
                            table_part['default'][dst_subnet.id][dst_net_obj.id][dst_service.id] = access

                        #from service to object
                        for src_service in src_net_obj.services:
                            access = self.has_access(src_net_obj, dst_net_obj, src_service, None)
                            table_part[src_service.id][dst_subnet.id][dst_net_obj.id]['default'] = access

                        #from service to service
                        for src_service in src_net_obj.services:
                            for dst_service in dst_net_obj.services:
                                access = self.has_access(src_net_obj, dst_net_obj, src_service, dst_service)
                                table_part[src_service.id][dst_subnet.id][dst_net_obj.id][dst_service.id] = access

        self._res_table = res_table

    def get_all(self):
        return self._res_table

    def _extract_service(self, subnet_id, net_object_id, service_id):
        try:
            return self._net_map.get_subnet(subnet_id).get_net_object(net_object_id).get_service(service_id)
        except:
            return None

    def get_reachable_services(self, net_object):
        if not self._res_table:
            # raise exeption
            return []

        res = []
        base_part = self._res_table[net_object.subnet.id][net_object.id]['default']
        for dest_subnets_part_key in base_part:
            dest_subnets_part = base_part[dest_subnets_part_key]
            for dest_net_obj_part_key in dest_subnets_part:
                dest_net_obj_part = dest_subnets_part[dest_net_obj_part_key]
                for dest_service_part_key in dest_net_obj_part:
                    dest_service_part = dest_net_obj_part[dest_service_part_key]
                    #нас интересуют реально существующие доступные сервисы
                    if dest_service_part and dest_service_part_key != "default":
                        res.append(self._extract_service(dest_subnets_part_key,
                                                         dest_net_obj_part_key, dest_service_part_key))

        return res
