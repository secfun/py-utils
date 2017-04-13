# coding: utf-8
import collections
import hashlib
import pickle
from functools import wraps

from django.core.cache import cache


def _get_function_sign(function_name, *args, **kwargs):
    args_hash = [str(arg.__hash__()) for arg in args]
    kargs_hash = [str(k.__hash__()) for k, v in kwargs.iteritems()]
    arg_hash = hashlib.md5(''.join(args_hash + kargs_hash)).hexdigest()

    return "{function_name}:{arg_hash}".format(function_name=function_name, arg_hash=arg_hash)


def ttl_cache(time_seconds=60 * 5):
    """
    time to live cahe
    缺点： 非线程安全
    :param time_seconds:
    :return:
    """

    def out_wrapper(function):
        @wraps(function)
        def inner_wrapper(*args, **kwargs):
            cache_key = _get_function_sign(function.__name__, *args, **kwargs)
            result = cache.get(cache_key)
            if result:
                return pickle.loads(result)
            else:
                result = function(*args, **kwargs)
                cache.set(cache_key, pickle.dumps(result), time_seconds)
                return result

        return inner_wrapper

    return out_wrapper


def lru_cache(capacity=64):
    """
    least recently used cache
    缺点：非线程安全，服务重启时候缓存丢失
    :param capacity:
    :return:
    """
    cache = collections.OrderedDict()

    def out_wrapper(function):
        @wraps(function)
        def inner_wrapper(*args, **kwargs):
            cache_key = _get_function_sign(function.__name__, *args, **kwargs)
            try:
                result = cache.pop(cache_key)
                cache[cache_key] = result
                return result
            except KeyError:
                if len(cache) >= capacity:
                    cache.popitem(last=False)
                result = function(*args, **kwargs)
                cache[cache_key] = result

                return result

        return inner_wrapper

    return out_wrapper
