# coding=utf-8


class NetMapException(Exception):
    pass

class BadNetMapId(NetMapException):
    def __unicode__(self):
        return u'No net map with such id'

    def __str__(self):
        return unicode(self).encode('utf-8')

class LastNetMapAchieved(NetMapException):
    def __unicode__(self):
        return u'Last net map achieved'

    def __str__(self):
        return unicode(self).encode('utf-8')

class LastSubNetAchieved(NetMapException):
    def __unicode__(self):
        return u'Last sub net achieved'

    def __str__(self):
        return unicode(self).encode('utf-8')

class LastNetObjectAchieved(NetMapException):
    def __unicode__(self):
        return u'Last net object achieved'

    def __str__(self):
        return unicode(self).encode('utf-8')

class LastNetInterfaceAchieved(NetMapException):
    def __unicode__(self):
        return u'Last net interface achieved'

    def __str__(self):
        return unicode(self).encode('utf-8')

class LastServiceAchieved(NetMapException):
    def __unicode__(self):
        return u'Last service achieved'

    def __str__(self):
        return unicode(self).encode('utf-8')

class BadSubNetId(NetMapException):
    def __unicode__(self):
        return u'No sub net with such id'

    def __str__(self):
        return unicode(self).encode('utf-8')

class BadFilterRuleId(NetMapException):
    def __unicode__(self):
        return u'No filter rule with such id'

    def __str__(self):
        return unicode(self).encode('utf-8')

class BadNetObjectId(NetMapException):
    def __unicode__(self):
        return u'No net object with such id'

    def __str__(self):
        return unicode(self).encode('utf-8')

class ErrorSaveToFile(NetMapException):
    def __unicode__(self):
        return u'Bad filename, try again'

    def __str__(self):
        return unicode(self).encode('utf-8')

class ErrorLoadFromFile(NetMapException):
    def __unicode__(self):
        return u'This file can not be open'

    def __str__(self):
        return unicode(self).encode('utf-8')

class NetMapToFileError(NetMapException):
    def __unicode__(self):
        return u'Net map to file error'

    def __str__(self):
        return unicode(self).encode('utf-8')

class BadNetInterfaceId(NetMapException):
    def __unicode__(self):
        return u'No net interface with such id'

    def __str__(self):
        return unicode(self).encode('utf-8')

class BadNetInterfaceId(NetMapException):
    def __unicode__(self):
        return u'No net interface with such id'

    def __str__(self):
        return unicode(self).encode('utf-8')

class BadServiceId(NetMapException):
    def __unicode__(self):
        return u'No service with such id'

    def __str__(self):
        return unicode(self).encode('utf-8')

class HostMustHaveOneInterface(NetMapException):
    def __unicode__(self):
        return u'Host must have only 1 interface'

    def __str__(self):
        return unicode(self).encode('utf-8')

class AlreadyLinked(NetMapException):
    def __unicode__(self):
        return u'Already linked'

    def __str__(self):
        return unicode(self).encode('utf-8')

class ErrorSetCidr(NetMapException):
    def __unicode__(self):
        return u'Error Set Cidr'

    def __str__(self):
        return unicode(self).encode('utf-8')

class ErrorSetGateway(NetMapException):
    def __unicode__(self):
        return u'Error Set Gateway'

    def __str__(self):
        return unicode(self).encode('utf-8')