import time
import requests
from .config import ME
import mf2py

def verify_code(client_id, redirect_uri, decoded_code):
    if int(time.time()) > decoded_code["expires"]:
        return "invalid_grant"

    if redirect_uri != decoded_code["redirect_uri"]:
        return "invalid_grant"

    if client_id != decoded_code["client_id"]:
        return "invalid_grant"

    return None

def get_rels(me_url):
    home = requests.get(ME)

    home_parsed = mf2py.parse(home.text)

    if home_parsed.get("rels") and home_parsed["rels"].get("me"):
        home_me_links = home_parsed["rels"]["me"]
    else:
        home_me_links = []

    for link in home_me_links:
        if link == me_url:
            return True

    return False