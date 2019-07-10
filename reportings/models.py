from __future__ import unicode_literals

FIELD_TYPES_CRITERIAS = {
    "TEXT": [
        {"criteria": "is", "criteria_kw": "exact"},
        {"criteria": "contains", "criteria_kw": "icontains"},
        {"criteria": "start with", "criteria_kw": "startswith"},
        {"criteria": "end with", "criteria_kw": "endswith"}],
    "NUMBER": [
        {"criteria": "is equal to", "criteria_kw": "exact"},
        {"criteria": "is greater than", "criteria_kw": "gt"},
        {"criteria": "is lower than", "criteria_kw": "lt"}],
    "DATETIME": [
        {"criteria": "is equal to", "criteria_kw": "exact"}],
}
