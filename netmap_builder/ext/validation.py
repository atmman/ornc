# coding=utf-8
from datetime import datetime
from netaddr import IPNetwork, AddrFormatError


class FieldValidationError(Exception):
    def __init__(self, name, value=''):
        self.name = name
        self.value = value

    def __unicode__(self):
        raise NotImplemented()

    def __str__(self):
        return unicode(self).encode('utf-8')


class EmptyValidationError(FieldValidationError):
    def __unicode__(self):
        return u'"%s" не должно быть пустым' % self.name

    def __str__(self):
        return unicode(self).encode('utf-8')


def required(name, value):
    """
    >>> required('field_name', 'aaa')

    >>> required('field_name', None) #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    EmptyValidationError: "field_name" ...

    >>> required('field_name', '') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    EmptyValidationError: "field_name" ...
    """

    if value in (None, ''):
        raise EmptyValidationError(name)


class NotEmptyValidationError(FieldValidationError):
    def __unicode__(self):
        return u'"%s" должно быть пустым' % self.name

    def __str__(self):
        return unicode(self).encode('utf-8')


def should_be_empty(name, value):
    """
    >>> should_be_empty('field_name', None)

    >>> should_be_empty('field_name', '')

    >>> should_be_empty('field_name', 'aaa') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    NotEmptyValidationError: "field_name" ...
    """

    if not value in (None, ''):
        raise NotEmptyValidationError(name)


class RegExValidationError(FieldValidationError):
    def __unicode__(self):
        return u'Значение "%s" для поля "%s" не соответствует требуемому формату' % (self.value, self.name)

    def __str__(self):
        return unicode(self).encode('utf-8')


def regex(re_obj):
    """

    >>> regex('abc')('field_name', 'abcd')

    >>> regex('abc')('field_name', 'ab') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    RegExValidationError: ...
    """
    if isinstance(re_obj, str) or isinstance(re_obj, unicode):
        import re
        re_obj = re.compile(re_obj)

    def validator(name, value):
        if not re_obj.search(value):
            raise RegExValidationError(name, value)
    return validator


class EmailValidationError(FieldValidationError):
    def __unicode__(self):
        return u'Значение "%s" поля "%s" не является email-ом' % (self.value, self.name)

    def __str__(self):
        return unicode(self).encode('utf-8')


def email(name, value):
    """

    >>> email('field_name', 'aa@bb.com')

    >>> email('field_name', '') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    EmailValidationError: ...

    >>> email('field_name', 'aa.com') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    EmailValidationError: ...
    """
    import re
    email_re = re.compile(
        r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
        # quoted-string, see also http://tools.ietf.org/html/rfc2822#section-3.2.5
        r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"'
        r')@((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?$)'  # domain
        r'|\[(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\]$', re.IGNORECASE)  # literal form, ipv4 address (SMTP 4.1.3)
    try:
        regex(email_re)(name, value)
    except RegExValidationError:
        raise EmailValidationError(name, value)


class LoginValidationError(FieldValidationError):
    def __unicode__(self):
        return u'Значение "%s" поля "%s" не является корректным логином. Используйте только латинские буквы, цифры и следующие символы: "-_@."' % (self.value, self.name)

    def __str__(self):
        return unicode(self).encode('utf-8')


class LatinOnlyValidationError(FieldValidationError):
    def __unicode__(self):
        return u'Значение "%s" поля "%s" может содержать только латинские буквы и пробел' % (self.value, self.name)

    def __str__(self):
        return unicode(self).encode('utf-8')


def latin_only(name, value):
    u"""

    >>> latin_only('field_name', 'Test')

    # Этот тест нормально выполняется только из __main__ из-за unicode специфики
    >>> latin_only('field_name', u'Тест') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    LatinOnlyValidationError: ...
    """
    import re
    latin_re = re.compile(r'^[-A-Za-z ]+$', re.IGNORECASE)
    try:
        regex(latin_re)(name, value)
    except RegExValidationError:
        raise LatinOnlyValidationError(name, value)


class RussianOnlyValidationError(FieldValidationError):
    def __unicode__(self):
        return u'Значение "%s" поля "%s" может содержать только латинские буквы и пробел' % (self.value, self.name)

    def __str__(self):
        return unicode(self).encode('utf-8')


def russian_only(name, value):
    u"""

    # Этот тест нормально выполняется только из __main__ из-за unicode специфики
    >>> russian_only('field_name', u'Тест')

    >>> russian_only('field_name', 'Test') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    RussianOnlyValidationError: ...
    """
    import re

    russian_re = re.compile(ur'^[-А-Яа-яЁё ]+$', re.IGNORECASE)
    try:
        regex(russian_re)(name, value)
    except RegExValidationError:
        raise RussianOnlyValidationError(name, value)


class ValueInValidationError(FieldValidationError):
    def __init__(self, name, value, values):
        super(ValueInValidationError, self).__init__(name, value)
        self.values = values

    def __unicode__(self):
        return u'Значение "%s" поля "%s" должно быть одним из %s' % (self.value, self.name, self.values)

    def __str__(self):
        return unicode(self).encode('utf-8')


def value_in(values):
    """

    >>> value_in([1, 2, 3])('field_name', 2)

    >>> value_in([1, 2, 3])('field_name', 5) #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    ValueInValidationError: ...
    """
    def validator(name, value):
        if value not in values:
            raise ValueInValidationError(name, value, values)
    return validator


class BoolValueValidationError(FieldValidationError):
    def __unicode__(self):
        return u'Значение "%s" поля "%s" может содержать только булево значение (true, false)' % (self.value, self.name)

    def __str__(self):
        return unicode(self).encode('utf-8')


def bool_value(name, value):
    """

    # Этот тест нормально выполняется только из __main__ из-за unicode специфики
    >>> bool_value('field_name', True)

    >>> bool_value('field_name', False)

    >>> bool_value('field_name', 10) #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    BoolValueValidationError: ...
    """
    if not isinstance(value, bool):
        raise BoolValueValidationError(name, value)


class DateStringValidationError(FieldValidationError):
    def __init__(self, name, value, date_format):
        super(DateStringValidationError, self).__init__(name, value)
        self.date_format = date_format

    def __unicode__(self):
        return u'Значение "%s" поля "%s" может содержать только строку с датой в формате "%s"' % (self.value, self.name, self.date_format)

    def __str__(self):
        return unicode(self).encode('utf-8')


def date_string(date_format):
    """

    >>> date_string('%Y-%m-%d')('field_name', '2000-01-07')

    >>> date_string('%Y-%m-%d')('field_name', '2000-13-07') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    DateStringValidationError: ...

    >>> date_string('%Y-%m-%d')('field_name', '10-07-2000') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    DateStringValidationError: ...
    """
    def validator(name, value):
        try:
            datetime.strptime(value, date_format)
        except ValueError:
            raise DateStringValidationError(name, value, date_format)

    return validator


def get_full_years(birthday, dt):
    if dt.month > birthday.month or (dt.month == birthday.month and dt.day >= birthday.day):
        return dt.year - birthday.year
    else:
        return dt.year - birthday.year - 1


class MaxAgeValidationError(FieldValidationError):
    def __init__(self, name, value, age_limit, to_date):
        super(MaxAgeValidationError, self).__init__(name, value)
        self.age_limit = age_limit
        self.to_date = to_date

    def __unicode__(self):
        return u'Значение "%s" поля "%s" содержит дату, в соответсвии с которой возраст на дату "%s" будет превышать максимально допустимый ("%s" года/лет)' % \
               (self.value, self.name, self.to_date, self.age_limit)

    def __str__(self):
        return unicode(self).encode('utf-8')


def max_age(age_limit, to_date):
    """

    >>> max_age(2, datetime(2001, 1, 1))('field_name', datetime(2000, 1, 1))

    >>> max_age(2, datetime(2003, 1, 1))('field_name', datetime(2000, 1, 1)) #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    MaxAgeValidationError: ...
    """
    def validator(name, value):
        full_years = get_full_years(value, to_date)
        if full_years > age_limit:
            raise MaxAgeValidationError(name, value, age_limit, to_date)

    return validator


class MinAgeValidationError(FieldValidationError):
    def __init__(self, name, value, age_limit, to_date):
        super(MinAgeValidationError, self).__init__(name, value)
        self.age_limit = age_limit
        self.to_date = to_date

    def __unicode__(self):
        return u'Значение "%s" поля "%s" содержит дату, в соответсвии с которой возраст на дату "%s" будет не соответствовать минимально допустимому ("%s" года/лет)' %\
               (self.value, self.name, self.to_date, self.age_limit)

    def __str__(self):
        return unicode(self).encode('utf-8')


def min_age(age_limit, to_date):
    """

    >>> min_age(2, datetime(2002, 1, 1))('field_name', datetime(2000, 1, 1))

    >>> min_age(3, datetime(2002, 1, 1))('field_name', datetime(2000, 1, 1)) #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    MinAgeValidationError: ...
    """
    def validator(name, value):
        full_years = get_full_years(value, to_date)
        if full_years < age_limit:
            raise MinAgeValidationError(name, value, age_limit, to_date)

    return validator


class MinDateValidationError(FieldValidationError):
    def __init__(self, name, value, date):
        super(MinDateValidationError, self).__init__(name, value)
        self.date = date

    def __unicode__(self):
        return u'Значение "%s" поля "%s" содержит дату, которая не соответствовует минимально допустимой дате "%s"' %\
               (self.value, self.name, self.date)

    def __str__(self):
        return unicode(self).encode('utf-8')


def min_date(date):
    """

    >>> min_date(datetime(2002, 1, 1))('field_name', datetime(2002, 1, 2))

    >>> min_date(datetime(2002, 1, 1))('field_name', datetime(2000, 1, 1)) #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    MinDateValidationError: ...
    """
    def validator(name, value):
        if value < date:
            raise MinDateValidationError(name, value, date)

    return validator


class MinLengthValidationError(FieldValidationError):
    def __init__(self, name, value, length):
        super(MinLengthValidationError, self).__init__(name, value)
        self.length = length

    def __unicode__(self):
        return u'Значение "%s" поля "%s" содержит данные, длина которых меньше минимально допустимой "%s"' %\
               (self.value, self.name, self.length)

    def __str__(self):
        return unicode(self).encode('utf-8')


def min_length(length):
    """

    >>> min_length(3)('field_name', 'asd')

    >>> min_length(3)('field_name', 'as') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    MinLengthValidationError: ...
    """
    def validator(name, value):
        if len(value) < length:
            raise MinLengthValidationError(name, value, length)

    return validator


class CidrValidationError(FieldValidationError):
    def __init__(self, name, value):
        super(CidrValidationError, self).__init__(name, value)

    def __unicode__(self):
        return u'Значение "%s" поля "%s" содержит неправильный CIDR' %\
               (self.value, self.name)

    def __str__(self):
        return unicode(self).encode('utf-8')


def cidr(name, value):
    """

    >>> cidr('field_name', '10.10.133.1/24')

    >>> cidr('field_name', '10.10.133.555/24') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    CidrValidationError: ...

    >>> cidr('field_name', '10.10..222/24') #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    CidrValidationError: ...
    """
    try:
        IPNetwork(value)
    except Exception:
        raise CidrValidationError(name, value)


def validate(name, value, *args):
    """

    @param name: имя поля, которое проверяется
    @param value: значение, которое надо проверить
    @param args: валидаторы
    @return: ничего
    @raise: одно из исключений-наследников FieldValidationError

    >>> validate('field_name', '', required) #doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    EmptyValidationError: "field_name" ...

    >>> validate('field_name', 'aa@bb.com', required, email) #doctest: +ELLIPSIS
    """
    if value in (None, ''):
        if not required in args:
            return

    for arg in args:
        arg(name, value)


if __name__ == "__main__":
    import sys
    reload(sys)
    sys.setdefaultencoding("UTF-8")
    import doctest
    doctest.testmod()