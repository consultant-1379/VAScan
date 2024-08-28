from node_hardening.hardening.base import BaseHardening, CommandExecutionException, StopHardeningExecution
from node_hardening.parsers import NTPOutputParser


class TimeSynchronisation(BaseHardening):
    section = 'TimeSynchronisation'


class NtpSyncEnabled(TimeSynchronisation):
    topic = 'ntp_sync_enabled'

    def check(self):
        cmd = '/usr/sbin/ntpq -p'
        out = self.ssh.run(cmd)
        parser = NTPOutputParser(out)
        actual_address = parser.parse()
        if not actual_address:
            raise StopHardeningExecution("Unable to determine the "
                                         "address of the ntp server")
        if self.description.ntp_server != actual_address:
            raise StopHardeningExecution("Peer server should be trying to "
                  "sync with the server %s but it is instead trying to sync "
                  "with IP address %s." % (self.description.ntp_server,
                                           actual_address))
        return True
