
import time
import simplejson
from urllib2 import HTTPError
from simplejson import JSONDecodeError
import requests


class NessusApiError(Exception):
    pass


class NessusRequest(object):

    request_attempts = 5
    seconds_between_attempts = 5

    def __init__(self, uri, access_key, secret_key):
        self.access_key = access_key
        self.secret_key = secret_key
        self.uri = uri

    def _request(self, path, method, **data):
        """
        """
        url = "%s%s" % (self.uri, path)
        headers = {'X-ApiKeys': 'accessKey=%s; secretKey=%s' %
                                (self.access_key, self.secret_key),
                   'Content-Type': 'application/json'}

        def open_request(attempts):
            func = getattr(requests, method)
            try:
                return func(url, data=simplejson.dumps(data), headers=headers,
                            verify=False)
            except HTTPError as err:
                if err.getcode() != 502:
                    raise err
                print("HTTPError occurred while trying to request the url "
                      "%s. %s. Trying again in %s seconds..." % (url, err,
                                                self.seconds_between_attempts))
                time.sleep(self.seconds_between_attempts)
                return open_request(attempts)
            except requests.exceptions.ChunkedEncodingError as err:
                print("ChunkedEncodingError occurred while trying to request "
                      "the url %s. %s. Trying again in %s seconds..." % (url,
                                           err, self.seconds_between_attempts))
                time.sleep(self.seconds_between_attempts)
                return open_request(attempts)

        attempts = 0
        response = open_request(attempts)
        # We should rise exception if the status code is not 'OK'
        if response.status_code != 200:
            raise NessusApiError(response.status_code, response.reason)
        # In case we try to download the Nessus report file the content
        # won't be json response but RAW file hence JSONDecodeError exception
        try:
            return response.json()
        except JSONDecodeError:
            return response.content

    def get(self, url, **data):
        return self._request(url, 'get', **data)

    def post(self, url, **data):
        return self._request(url, 'post', **data)

    def put(self, url, **data):
        return self._request(url, 'put', **data)

    def delete(self, url, **data):
        return self._request(url, 'delete', **data)


class Resource(object):

    base_uri = None
    list_uri = base_uri
    get_uri = "%s/%%s" % base_uri
    create_uri = base_uri
    delete_uri = get_uri

    def __init__(self, api):
        self.api = api

    def _validate_base_uri(self):
        if self.base_uri is None:
            raise Exception('The attribute base_uri must be defined.')

    def list(self, *args):
        self._validate_base_uri()
        url = self.list_uri % args
        return self.api.request.get(url)

    def get(self, *args):
        self._validate_base_uri()
        return self.api.request.get(self.get_uri % args)

    def create(self, **kwargs):
        self._validate_base_uri()
        return self.api.request.post(self.create_uri, **kwargs)

    def delete(self, *args):
        self._validate_base_uri()
        return self.api.request.delete(self.delete_uri % args)


class ResourceObject(object):

    def __init__(self, api, **data):
        self.api = api
        self._data = data
        for key, value in data.items():
            setattr(self, key, value)

    def __repr__(self):
        get = lambda x: getattr(self, x, None)
        title = get('name') or get('title') or get('id') or get('uuid')
        return "<%s: %s>" % (self.__class__.__name__, title)
