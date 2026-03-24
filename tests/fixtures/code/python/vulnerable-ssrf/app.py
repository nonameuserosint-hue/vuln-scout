import requests


def fetch_profile(target):
    return requests.get(target, timeout=5)
