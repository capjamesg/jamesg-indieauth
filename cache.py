import datetime
from datetime import timedelta

from cachetools import TLRUCache


def datetime_ttu(_key, value, now):
    return now + timedelta(hours=1)


h_card_cache = TLRUCache(maxsize=100, ttu=datetime_ttu, timer=datetime.datetime.now)
