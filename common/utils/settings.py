# -*- coding: utf-8 -*-

from app import settings

# 
# def is_restricted():
#     """Check if the instance is usage restricted."""
#     if "RESTRICTED_USAGE" in dir(settings) and settings.RESTRICTED_USAGE is True:
#         return True
#     return False


def is_restricted():
    """Check if the instance run PRO edition."""
    if "PRO_EDITION" in dir(settings) and settings.PRO_EDITION is True:
        return True
    return False
