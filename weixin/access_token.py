# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
import logging
import requests

from django.core.cache import cache

log = logging.getLogger(__name__)


def get_access_token(app, app_key, app_secret):
    # requests获取access_token的方法
    cache_key = app + '_weixin_access_token'
    access_token = cache.get(cache_key)

    if access_token:
        return access_token

    url = 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={}&secret={}'.format(app_key,
                                                                                                           app_secret)

    try:
        response = requests.get(url).json()
    except Exception as ex:
        log.error("response: {response}, exception: {exception}".format(response=str(response), exception=str(ex)))
        return ''

    access_token = response.get('access_token')
    expires_in = response.get('expires_in')

    if access_token and expires_in:
        expires_in = int(expires_in)
        cache.set(cache_key, access_token, timeout=int(expires_in / 120.0 * 1))
        return access_token
    return ''
