import re
from node_hardening.hardening.base import BaseHardening, \
                              CommandExecutionException, StopHardeningExecution
from node_hardening.parsers import NetstatTulpnOutputParser

class SecuringServices(BaseHardening):
    section = 'SecuringServices'


class MaxLogins(SecuringServices):
    topic = 'max_logins'

    max_logins_regex = re.compile(r'^\s*\*\s+\-\s+maxlogins\s+(\d+).*')
    limits_conf = "/etc/security/limits.conf"

    def check(self):
        out = self.ssh.run("/bin/cat %s" % self.limits_conf)
        current_max_logins = 0
        for line in out.splitlines():
            match = self.max_logins_regex.match(line)
            if match:
                current_max_logins = match.groups()[0]
                break
        return int(current_max_logins)

    def harden(self):
        max_logins = self.expected_value
        report = dict()
        limits_conf = "/etc/security/limits.conf"
        try:
            cmd = "/bin/grep -i maxlogins %s" % limits_conf
            out = self.ssh.run(cmd)
            for line in out.splitlines():
                if line.startswith('#'):
                    continue
                # delete any previous settings if they exist
                cmd = "/bin/sed -i '/%s/d' %s" % (line, limits_conf)
                out = self.ssh.run(cmd)
        except CommandExecutionException as error:
            if error.status_code == 1:
                report['Not found'] = "No previous settings found"
        cmd = "/bin/echo '*         -           maxlogins       %s' >> %s" % (max_logins, self.limits_conf)
        self.ssh.run(cmd)
        report['max_logins'] = "File %s updated with maxlogins set to %s." % (self.limits_conf, max_logins)
        return report


class TelnetClientInstalled(SecuringServices):
    topic = 'telnet_client_installed'
    package = 'telnet'

    def check(self):
        is_installed = True
        cmd = "/bin/rpm -q %s" % self.package
        try:
            self.ssh.run(cmd)
        except CommandExecutionException as err:
            if err.status_code == 1:
                is_installed = False
            else:
                raise
        return is_installed

    def harden(self):
        report = dict()
        should_be_installed = self.expected_value
        if should_be_installed:
            raise NotImplementedError("%s True case must be implemented" %
                                         self.topic)
        else:
            self._remove_package(self.package)
        return report


class TelnetServerInstalled(TelnetClientInstalled):
    topic = 'telnet_server_installed'
    package = 'telnet-server'


class FtpInstalled(TelnetClientInstalled):
    topic = 'ftp_installed'
    package = 'vsftpd'


class PortsNotInUse(SecuringServices):
    topic = 'ports_not_in_use'

    def __init__(self, *args, **kwargs):
        super(PortsNotInUse, self).__init__(*args, **kwargs)
        self._netstat_data_cache = None

    def _is_in_use(self, port):
        port = int(port)
        if self._netstat_data_cache is None:
            out = self.ssh.run('/bin/netstat -tulpn')
            parser = NetstatTulpnOutputParser(out.strip())
            self._netstat_data_cache = parser.parse()
        data = self._netstat_data_cache
        in_use = reduce(lambda a, b: a + b,
                        [[i['local']['port'] == port for i in proc]
                         for proc in data.values()])
        return any(in_use)

    def check(self):
        ports = self.expected_value
        return [p for p in ports if not self._is_in_use(p)]

    def harden(self):
        ports = self.expected_value
        errors = []
        killed = []
        for port in ports:
            if self._is_in_use(port):
                try:
                    self.ssh.run("kill $(lsof -t -i:%d)" % port)
                except CommandExecutionException as err:
                    raise StopHardeningExecution((port, str(err)))
                killed.append(port)
        if errors:
            errors = ', '.join(["%s: %s" % (p, e) for p, e in errors])
            raise StopHardeningExecution("Failed to kill process on the "
                                         "following restricted ports: %s" %
                                         errors)
        return "Processes using the following ports were killed: %s" % killed