from nessusapi.base import NessusRequest, NessusApiError
from nessusapi.resources import EditorResource, ScansResource, PolicyResource


class NessusApi(object):

    def __init__(self, uri, access_key, secret_key):
        self.request = NessusRequest(uri, access_key, secret_key)
        self.editor = EditorResource(self)
        self.scans = ScansResource(self)
        self.policies = PolicyResource(self)
