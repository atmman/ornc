# coding=utf8

_last_id_id = 0


def generate_id():
    global _last_id_id
    _last_id_id += 1
    return str(_last_id_id)

