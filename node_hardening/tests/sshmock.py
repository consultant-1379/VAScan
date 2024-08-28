
from node_hardening.ssh import SshScpClient


class SshScpClientMock(SshScpClient):

    def __init__(self, *args, **kwargs):
        super(SshScpClientMock, self).__init__(*args, **kwargs)
        self.outputs = []
        self.errors = []

    def connect(self):
        pass

    def run(self, cmd, timeout=None, su=None, expects=None):
        for regex, output in self.outputs:
            if regex.match(cmd):
                return 0, output, ''
        for regex, status, output in self.errors:
            if regex.match(cmd):
                return status, '', output
        return 127, '', "%s: command not found" % cmd.split()[0]
