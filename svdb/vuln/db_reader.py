#import logging
import sqlite3
import os.path

from svdb.id.cpe import CPEID
from svdb.id.cve import CVEID


#logger = logging.getLogger("svdb.vuln.db_reader")
#logger.setLevel(logging.INFO)


class DB(object):
    """DB layer
    """
    
    @classmethod
    def init(cls, db_path='vuln.sqlite'):
        if db_path == 'vuln.sqlite':
            cls._db_path = os.path.join(os.path.dirname(__file__), db_path)
        else:
            cls._db_path = db_path
        
        cls._con = sqlite3.connect(cls._db_path)
        cls._con.row_factory = sqlite3.Row
        cls._cur = cls._con.cursor()
#        logger.debug("Opened DB: %s" % cls._db_path)
        
    @classmethod
    def get_cpe_by_cve(cls, cve_id):
        """ Return list of CPEID by CVE-ID
        @param cve_id: string with CVE-ID or CVEID instance
        @return: list of tuples (CPEID instance, Official name) 
        """
        
        if not isinstance(cve_id, CVEID):
            cve_id = CVEID(cve_id)
        
        sql = """
                SELECT pr.part, pr.vendor, pr.product, concr_pr.version,
                        concr_pr.pr_update, concr_pr.edition, concr_pr.language,
                        pr.official_name
                FROM vulnerabilities AS vulns
                JOIN products_to_vulnerabilities AS pr2vulns ON pr2vulns.vuln_id = vulns.id
                JOIN concrete_products AS concr_pr ON concr_pr.id = pr2vulns.concrete_product_id
                JOIN products AS pr ON pr.id = concr_pr.product_id
                WHERE cve_id='%s'
                """ % cve_id
        
        res = cls._cur.execute(sql).fetchall()
        
        ret = []
        for row in res:
            cpeid = CPEID('', row['part'], row['vendor'], row['product'],
                          row['version'], row['pr_update'],
                          row['edition'], row['language'])
            #ret.append((cpeid, row['official_name'])) old version
            ret.append(str(cpeid))
        
        return ret
    
    @classmethod
    def get_cve_by_cpe(cls, cpe_id):
        """ Return list of CVE-ID by CPEID
        @param cve_id: string with CPEID instance
        @return: list of tuples (CVE-ID instance), Official name) 
        """
        if not isinstance(cpe_id, CPEID):
            cpe_id = CPEID(cpe_id)
            
        query = """
                SELECT cve_id, summary
                FROM vulnerabilities AS vulns
                JOIN products_to_vulnerabilities AS pr2vulns ON pr2vulns.vuln_id = vulns.id
                JOIN concrete_products AS concr_pr ON concr_pr.id = pr2vulns.concrete_product_id
                JOIN products AS pr ON pr.id = concr_pr.product_id
                WHERE pr.part='%s' AND pr.vendor='%s' AND pr.product='%s' 
                      AND concr_pr.version='%s' AND  concr_pr.pr_update='%s' AND  concr_pr.edition='%s' AND  language='%s'
                """ % (cpe_id.get_part_info(), cpe_id.get_vendor_info(), cpe_id.get_product_info(), 
                       cpe_id.get_version_info(), cpe_id.get_update_info(), cpe_id.get_edition_info(), cpe_id.get_language_info())

        res = cls._cur.execute(query).fetchall()
            
        ret = []
        for row in res:
            cve_id = CVEID(row[0])
            #ret.append(str(cve_id))
            ret.append((str(cve_id), str(row[1])))
        
        return ret
