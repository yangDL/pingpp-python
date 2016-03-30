import logging
import sys
import os



logger = logging.getLogger('pingpp')

__all__ = ['StringIO', 'parse_qsl', 'json', 'utf8']

try:
    # When cStringIO is available
    import cStringIO as StringIO
except ImportError:
    import StringIO

try:
    from urlparse import parse_qsl
except ImportError:
    # Python < 2.6
    from cgi import parse_qsl

try:
    import json
except ImportError:
    json = None

if not (json and hasattr(json, 'loads')):
    try:
        import simplejson as json
    except ImportError:
        if not json:
            raise ImportError(
                "Ping++ requires a JSON library, such as simplejson. "
                "HINT: Try installing the "
                "python simplejson library via 'pip install simplejson' or "
                "'easy_install simplejson'.")
        else:
            raise ImportError(
                "Ping++ requires a JSON library with the same interface as "
                "the Python 2.6 'json' library.  You appear to have a 'json' "
                "library with a different interface.  Please install "
                "the simplejson library.  HINT: Try installing the "
                "python simplejson library via 'pip install simplejson' "
                "or 'easy_install simplejson'.")


def utf8(value):
    if isinstance(value, unicode) and sys.version_info < (3, 0):
        return value.encode('utf-8')
    else:
        return value


def is_appengine_dev():
    return ('APPENGINE_RUNTIME' in os.environ and
            'Dev' in os.environ.get('SERVER_SOFTWARE', ''))


def webhooks_verify(path_pubkey, private_sign, req_data):
    """ path_pubkey : 公钥文件路径，内容为ping++提供的公钥(账户和设置 - Ping++ 公钥)
        private_sign: ping++对应的私钥签名后的字符串
        req_data    : 请求的json格式字符串，不要get_json(),因为会改变字段的顺序，直接获取原始字符串即可
        备注：遇到一个坑，直接从官网上copy公钥时，vim保存文件时会多一个字符，导致验算不通过，推荐notepad++保存
              最后一行不要有换行符
    """
    import base64
    
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA256

    def decode_base64(data):
        missing_padding = 4 - len(data) % 4
        if missing_padding:
            data += b'='*missing_padding
        return base64.decodestring(data)

    sig = decode_base64(private_sign)
    req_data = req_data.encode('utf-8')
    digest = SHA256.new(req_data)
    pubkey = RSA.importKey(open(path_pubkey).read())
    pkcs = PKCS1_v1_5.new(pubkey)

    return pkcs.verify(digest, sig)


def webhooks_verify_for_flask(path_pubkey, request):
    private_sign = request.headers['x-pingplusplus-signature']
    req_data = request.data
    return webhooks_verify(path_pubkey, private_sign, req_data)
