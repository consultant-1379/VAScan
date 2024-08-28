
from .base import NessusRequest
from .resources import EditorResource, ScansResource


class NessusApi(object):

    def __init__(self, uri, access_key, secret_key):
        self.request = NessusRequest(uri, access_key, secret_key)
        self.editor = EditorResource(self)
        self.scans = ScansResource(self)
