import datetime
from dateutil.parser import parse

def ValidTimestamp(timestamp, min):
    now = datetime.datetime.now()
    date = now.strftime('%Y-%m-%d %H:%M:%S')
    date1 = parse(timestamp)
    date2 = parse(date)
    result = (date2 - date1).total_seconds() / 60
    return result < min  # 小于两分钟


def ValidTimestamp2(timestamp1, timestamp2, min):
    date1 = parse(timestamp1)
    date2 = parse(timestamp2)
    result = (date2 - date1).total_seconds() / 60
    return abs(result) < min  # 小于两分钟