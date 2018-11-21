# -*- coding: utf-8 -*-


def unicode_escape(unistr):
    """
    Tidys up unicode entities into HTML friendly entities.

    Takes a unicode string as an argument

    Returns a unicode string
    """
    import htmlentitydefs
    escaped = ""

    for char in unistr:
        if ord(char) in htmlentitydefs.codepoint2name:
            name = htmlentitydefs.codepoint2name.get(ord(char))
            entity = htmlentitydefs.name2codepoint.get(name)
            escaped += "&#" + str(entity)

        else:
            escaped += char

    return escaped
