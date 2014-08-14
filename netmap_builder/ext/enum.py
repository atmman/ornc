
class enum(object):
    @classmethod
    def items(cls):
        return dict((key, val) for key, val in cls.__dict__.iteritems() if key not in ('__module__', '__doc__'))

    @classmethod
    def values(cls):
        return cls.items().values()

    @classmethod
    def names(cls):
        return cls.items().keys()