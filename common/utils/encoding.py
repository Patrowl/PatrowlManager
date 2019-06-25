# -*- coding: utf-8 -*-

from datetime import date, datetime
from uuid import UUID
import html.entities


def unicode_escape(unistr):
    """
    Tidys up unicode entities into HTML friendly entities.
    Takes a unicode string as an argument
    Returns a unicode string
    """

    escaped = ""
    for char in unistr:
        if ord(char) in html.entities.codepoint2name:
            name = html.entities.codepoint2name.get(ord(char))
            entity = html.entities.name2codepoint.get(name)
            escaped += "&#" + str(entity)

        else:
            escaped += char

    return escaped


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        # if the obj is uuid, we simply return the value of uuid
        return obj.hex
    raise TypeError("Type %s not serializable" % type(obj))
