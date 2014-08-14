from netmap_builder.ext.enum import enum
from netmap_builder.ext.serialization import JsonSerializableObject


class SECURITY_PROTECTION_VALUES():
    SP_ALLOWS_ADMIN_ACCESS = 0
    SP_ALLOWS_USER_ACCESS = 1
    SP_ALLOWS_OTHER_ACCESS = 2
    SP_UNDEFINED = 3


SECURITY_PROTECTION_VALUES_NAMES = {
    SECURITY_PROTECTION_VALUES.SP_ALLOWS_ADMIN_ACCESS: "SP_ALLOWS_ADMIN_ACCESS",
    SECURITY_PROTECTION_VALUES.SP_ALLOWS_USER_ACCESS: "SP_ALLOWS_USER_ACCESS",
    SECURITY_PROTECTION_VALUES.SP_ALLOWS_OTHER_ACCESS: "SP_ALLOWS_OTHER_ACCESS",
    SECURITY_PROTECTION_VALUES.SP_UNDEFINED: "SP_UNDEFINED",
}


class ACCESS_VECTOR_VALUES(enum):
    LOCAL = 1
    ADJANCED_NETWORK = 2
    NETWORK = 3


ACCESS_VECTOR_VALUES_NAMES = {
    ACCESS_VECTOR_VALUES.LOCAL: "LOCAL",
    ACCESS_VECTOR_VALUES.ADJANCED_NETWORK: "ADJANCED_NETWORK",
    ACCESS_VECTOR_VALUES.NETWORK: "NETWORK",
}


class ACCESS_COMPLEXITY_VALUES(enum):
    HIGH = 1
    MEDIUM = 2
    LOW = 3


ACCESS_COMPLEXITY_VALUES_NAMES = {
    ACCESS_COMPLEXITY_VALUES.HIGH: "HIGH",
    ACCESS_COMPLEXITY_VALUES.MEDIUM: "MEDIUM",
    ACCESS_COMPLEXITY_VALUES.LOW: "LOW",
}


class AUTHENTICATION_VALUES(enum):
    authMULTIPLE = 1
    authSINGLE = 2
    authNONE = 3


AUTHENTICATION_VALUES_NAMES = {
    AUTHENTICATION_VALUES.authMULTIPLE: "MULTIPLE",
    AUTHENTICATION_VALUES.authSINGLE: "SINGLE",
    AUTHENTICATION_VALUES.authNONE: "NONE",
}


class IMPACT_VALUES(enum):
    iNONE = 1
    iPARTIAL = 2
    iCOMPLETE = 3


IMPACT_VALUES_NAMES = {
    IMPACT_VALUES.iNONE: "NONE",
    IMPACT_VALUES.iPARTIAL: "PARTIAL",
    IMPACT_VALUES.iCOMPLETE: "COMPLETE",
}


class CVSSMetrics(JsonSerializableObject):

    def __init__(self, security_protection=0, access_vector=0, access_complexity=0, authentication=0,
                 confidentiality_impact=0, integrity_impact=0, availability_impact=0, score=0):
        self.security_protection = int(security_protection)
        self.access_vector = int(access_vector)
        self.access_complexity = int(access_complexity)
        self.authentication = int(authentication)
        self.confidentiality_impact = int(confidentiality_impact)
        self.integrity_impact = int(integrity_impact)
        self.availability_impact = int(availability_impact)
        self.score = score

    def full_description(self):
        return '\n'.join([
            "ACCESS VECTOR:" + ACCESS_VECTOR_VALUES_NAMES[self.access_vector],
            "ACCESS COMPLEXITY:" + ACCESS_COMPLEXITY_VALUES_NAMES[self.access_complexity],
            "AUTH:" + AUTHENTICATION_VALUES_NAMES[self.authentication],
            "AVAILABILITY IMPACT:" + IMPACT_VALUES_NAMES[self.availability_impact],
            "CONFIDENTIALITY IMPACT:" + IMPACT_VALUES_NAMES[self.confidentiality_impact],
            "INTEGRITY IMPACT:" + IMPACT_VALUES_NAMES[self.integrity_impact]
        ])

    def __eq__(self, other):
        return self.security_protection == other.security_protection and \
               self.access_vector == other.access_vector and \
               self.access_complexity == other.access_complexity and \
               self.authentication == other.authentication and \
               self.confidentiality_impact == other.confidentiality_impact and \
               self.integrity_impact == other.integrity_impact and \
               self.availability_impact == other.availability_impact

    def __hash__(self):
        return hash((self.security_protection, self.access_vector, self.access_complexity,
                     self.authentication, self.confidentiality_impact, self.integrity_impact,
                     self.availability_impact))

    def __unicode__(self):
        return ';'.join([
            "AV:" + ACCESS_VECTOR_VALUES_NAMES[self.access_vector],
            "AC:" + ACCESS_COMPLEXITY_VALUES_NAMES[self.access_complexity],
            "Auth:" + AUTHENTICATION_VALUES_NAMES[self.authentication],
            "AI:" + IMPACT_VALUES_NAMES[self.availability_impact],
            "CI:" + IMPACT_VALUES_NAMES[self.confidentiality_impact],
            "II:" + IMPACT_VALUES_NAMES[self.integrity_impact]
        ])

    def __str__(self):
        return unicode(self).encode('utf-8')

    __repr__ = __str__