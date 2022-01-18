import datetime


def validate_datetime(date_text):
    # print(date_text)
    try:
        return datetime.datetime.strptime(date_text, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return False
