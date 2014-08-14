# coding=utf-8
import json
import os
import sqlite3

from cvss_metrics import CVSSMetrics
from vulnerability import Vulnerability
from netmap_builder.ext.enum import enum


class VENDOR_TYPE_VALUES(enum):
    APPLICATION = 0
    HARDWARE = 1
    OTHER = 2


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


_application_names = []
_hardware_names = []
_other_names = []


class ServiceDatabaseManager(object):

    def __init__(self):
        self._conn = None

    def __enter__(self):
        ROOT_PATH = os.path.dirname(__file__)
        path = ROOT_PATH + '/../db/vuln.sqlite'

        self._conn = sqlite3.connect(path)
        self._conn.row_factory = dict_factory
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._conn.close()

    def get_vendors_by_type(self, vendor_type):
        """
        brief Возвращает список производителей для заданного типа продукта
        param service_type - Интересующий нас тип
        return Список строк - названий производителей
        """

        def _get_vendors_from_db(vendor_type):
            query_string = "SELECT DISTINCT vendor FROM products WHERE part=? ORDER BY vendor;"
            cursor = self._conn.cursor()
            return cursor.execute(query_string, (vendor_type, )).fetchall()

        if vendor_type == VENDOR_TYPE_VALUES.APPLICATION:
            global _application_names
            if _application_names:
                return _application_names
            else:
                _application_names = _get_vendors_from_db('a')
                return _application_names

        elif vendor_type == VENDOR_TYPE_VALUES.HARDWARE:
            global _hardware_names
            if _hardware_names:
                return _hardware_names
            else:
                _hardware_names = _get_vendors_from_db('h')
                return _hardware_names

        elif vendor_type == VENDOR_TYPE_VALUES.OTHER:
            global _other_names
            if _other_names:
                return _other_names
            else:
                _other_names = _get_vendors_from_db('o')
                return _other_names

    def get_products_by_vendor(self, vendor):
        """
        brief Возвращает список продуктов для заданного производителя
        param vendor - Интересующий нас производитель
        return Список строк - названий продуктов
        """
        result = []
        query_string = "SELECT * FROM products WHERE vendor=? ORDER BY product;"

        result = self._conn.cursor().execute(query_string, (vendor, )).fetchall()
        return result

    def get_services_by_product(self, product_id):
        """
        brief Возвращает список CPE
        param product_id - Интересующий нас продукт
        return Список идентификаторов в БД
        """

        query_string = "SELECT * FROM products WHERE id=?;"
        product = self._conn.cursor().execute(query_string, (product_id, )).fetchone()

        query_string = "SELECT * FROM concrete_products WHERE product_id=?;"
        service_params = self._conn.cursor().execute(query_string, (product_id, )).fetchall()

        cpe_list = [
            {'cpe': ("cpe:/%s:%s:%s:%s:%s:%s:%s" % (product['part'], product['vendor'], product['product'],
                                            service_param['version'], service_param['pr_update'],
                                            service_param['edition'], service_param['language'])).rstrip(':'),
             'id': service_param['id']}
            for service_param in service_params
        ]
        return cpe_list

    def get_vulnerabilities_by_service(self, service_id):
        """
        brief Возвращает список уяз
        param product_version_id - Интересующий нас сервис в виде его идентификатора в БД
        return Контейнер с идентификаторами уязвимостей в БД
        """
        query_string = """
            SELECT * FROM vulnerabilities,
             products_to_vulnerabilities WHERE vulnerabilities.id=products_to_vulnerabilities.vuln_id
             AND products_to_vulnerabilities.concrete_product_id=?;
        """
        vulns = self._conn.cursor().execute(query_string, (service_id, )).fetchall()

        vulns = [Vulnerability(vuln['cve_id'], vuln['summary'], vuln['vuln_date'][:10],
                               CVSSMetrics(vuln['security_protection'], vuln['access_vector'],
                                                  vuln['access_complexity'], vuln['authentication'],
                                                  vuln['confidentiality_impact'], vuln['integrity_impact'],
                                                  vuln['availability_impact'], vuln['score']))
                 for vuln in vulns]

        return vulns

    def get_service_info(self, service_id):
        query_string = "SELECT * FROM concrete_products WHERE id=?;"
        service_param = self._conn.cursor().execute(query_string, (service_id, )).fetchone()

        query_string = "SELECT * FROM products WHERE id=?;"
        product = self._conn.cursor().execute(query_string, (service_param['product_id'], )).fetchone()

        vulns = self.get_vulnerabilities_by_service(service_id)

        return { 'cpe': ("cpe:/%s:%s:%s:%s:%s:%s:%s" % (product['part'], product['vendor'], product['product'],
                                            service_param['version'], service_param['pr_update'],
                                            service_param['edition'], service_param['language'])).rstrip(':'),
                 'vulns': vulns
        }

    def get_suggestions_for_services(name, version):
        """
        brief Получить предположения для сервиса

        param name Имя сервиса
        param version Версия сервиса

        return Список идентификаторов продуктов
        """
        pass

if __name__ == '__main__':

    manager = ServiceDatabaseManager()

    def make_cpe_list(vendor_type):
        cpe_list = []

        vendors = manager.get_vendors_by_type(vendor_type)
        for vendor in vendors:
            products = manager.get_products_by_vendor(vendor)

            for product in products:
                services = manager.get_services_by_product(product['id'])

                for service in services:
                    cpe = ("cpe:/%s:%s:%s:%s:%s:%s:%s" % (product['part'], product['vendor'], product['product'],
                        service['version'], service['pr_update'], service['edition'], service['language'])).rstrip(':')
                    cpe_list.append({'text': cpe, 'value': service['id']})

                    print cpe

        return cpe_list

    cpe_list = make_cpe_list(VENDOR_TYPE_VALUES.APPLICATION) + make_cpe_list(VENDOR_TYPE_VALUES.HARDWARE) + \
        make_cpe_list(VENDOR_TYPE_VALUES.OTHER)

    f = open('../../front_end/static/js/cpe_list.js', 'w')
    cpe_list_json = json.dumps(cpe_list, f)
    f.write('var cpe_list = ' + cpe_list_json)
    f.close()

    print 'done'