import json

import oauth2 as oauth
import six
from aweber_api.base import APIException
from requests_oauthlib import OAuth1Session

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode


class OAuthAdapter(object):
    def __init__(self, key, secret, base):
        self.key = key
        self.secret = secret
        self.api_base = base
        self.consumer = oauth.Consumer(key=self.key, secret=self.secret)
        self.oauth_config = dict(
            client_key=self.key, client_secret=self.secret,
            resource_owner_key=None, resource_owner_secret=None, verifier=None
        )
        self.oauth_client = OAuth1Session

    @staticmethod
    def _parse(response):
        try:
            data = json.loads(response)
            if not data or data == '':
                return response
            return data
        except:
            pass
        return response

    def get_request_token(self, url, data=None):
        body = self._prepare_request_body('POST', data)
        return self.oauth_client(**self.oauth_config).fetch_request_token(url, data=body)

    def get_access_token(self, url, data=None):
        self.oauth_config.update(
            resource_owner_key=self.user.request_token,
            resource_owner_secret=self.user.token_secret,
            verifier=data['oauth_verifier'])
        return self.oauth_client(**self.oauth_config).fetch_access_token(url)

    def request(self, method, url, data=None, response='body'):
        url = self._expand_url(url)
        body = self._prepare_request_body(method, data or dict())

        if method == 'GET' and body is not None and body is not '':
            if '?' in url:
                url = '{0}&{1}'.format(url, body)
            else:
                url = '{0}?{1}'.format(url, body)

        resp = self.oauth_client(
            client_key=self.key, client_secret=self.secret,
            resource_owner_key=self.user.access_token,
            resource_owner_secret=self.user.token_secret).get(url)

        content = resp.content
        if int(resp.status_code) >= 400:
            """
            API Service Errors:

            Please review the Exception that is raised it should indicate
            what the error is.

            refer to https://labs.aweber.com/docs/troubleshooting for more
            details.
            """
            content = json.loads(content)
            error = content.get('error', {})
            error_type = error.get('type')
            error_msg = error.get('message')
            raise APIException('{0}: {1}'.format(error_type, error_msg))
        if isinstance(content, six.binary_type):
            content = content.decode('utf-8')
        if response == 'body' and isinstance(content, six.string_types):
            return self._parse(content)
        if response == 'status':
            return resp.status_code
        if response == 'headers':
            return resp.headers
        return None

    def _expand_url(self, url):
        if not url[:4] == 'http':
            return '{0}{1}'.format(self.api_base, url)
        return url

    def _get_client(self):
        token = self.user.get_highest_priority_token()
        if token:
            token = oauth.Token(token, self.user.token_secret)
            client = oauth.Client(self.consumer, token=token)
        else:
            client = oauth.Client(self.consumer)
        return client

    @staticmethod
    def _prepare_request_body(method, data):
        if method not in ['POST', 'GET', 'PATCH'] or len(data.keys()) == 0:
            return ''
        if method in ['POST', 'GET']:
            # WARNING: non-primative items in data must be json serialized.
            for key in data:
                if type(data[key]) in [dict, list]:
                    data[key] = json.dumps(data[key])
            return urlencode(data)
        if method == 'PATCH':
            return json.dumps(data)
