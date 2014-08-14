from datetime import datetime, timedelta

ISO_DATE_FORMATS = [
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%dT%H:%M',
    '%Y-%m-%dT%H:%M:%S.%f',
    '%Y-%m-%dT%H:%M:%S.%fZ',
    '%Y-%m-%dT%H:%M:%SZ',
    '%Y-%m-%d']

def iso_to_datetime(iso_dt):
    for format in ISO_DATE_FORMATS:
        try:
            return datetime.strptime(iso_dt, format)
        except ValueError:
            continue


def iso_to_date(iso_d):
    return datetime.strptime(iso_d, '%Y-%m-%d').date()


def minutes_to_hh_mm(minutes):
    try:
        minutes = int(minutes)
    except ValueError:
        return None

    return '{hours}:{minutes}'.format(hours=minutes/60, minutes=minutes%60)


def get_valid_future_datetimes(base_datetime, *args):
    dts = []
    for dt_params in args:
        dt = base_datetime + timedelta(**dt_params)
        if dt <= datetime.now():
            continue
        dts.append(dt)

    return dts
