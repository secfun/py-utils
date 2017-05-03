# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import hashlib
import json
import logging
import time

import requests
from django.core.cache import cache

from .utils import random_string

log = logging.getLogger(__name__)


def get_jsapi_ticket(access_token):
    cache_key = "weixin_js_api_token"
    js_ticket = cache.get(cache_key)
    # log.info(js_ticket)
    # if js_ticket:
    #    return js_ticket

    api_url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token={token}&type=jsapi".format(
        token=access_token)
    response = requests.get(api_url)
    assert response.status_code == 200
    json_response = json.loads(response.content)
    log.info(response.content)

    if json_response['errcode'] == 0:
        ticket = json_response["ticket"]
        expires_in = json_response.get('expires_in')
        cache.set(cache_key, access_token, timeout=int(expires_in / 4.0 * 3))
        return ticket

    return ""


def get_jsapi_params(access_token, url):
    param_template = "jsapi_ticket={jsapi_ticket}&noncestr={noncestr}&timestamp={timestamp}&url={url}"
    js_ticket = get_jsapi_ticket(access_token)
    noncestr = random_string()
    timestamp = int(time.time())
    str_to_sign = param_template.format(
        jsapi_ticket=js_ticket,
        noncestr=noncestr,
        timestamp=timestamp,
        url=url)
    log.info(str(str_to_sign))
    signature = hashlib.sha1(str_to_sign).hexdigest()

    return {"noncestr": noncestr,
            "timestamp": timestamp,
            "jsapi_ticket": js_ticket,
            "url": url,
            "signature": signature}
