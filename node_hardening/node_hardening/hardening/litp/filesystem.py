from node_hardening.hardening.base import BaseHardening, CommandExecutionException, StopHardeningExecution


class FileSystem(BaseHardening):
    section = 'FileSystem'


class AutoMountEnabled(FileSystem):
    topic = 'auto_mount_enabled'

    def check(self):
        try:
            self.ssh.run('/sbin/service autofs status')
            return True
        except CommandExecutionException:
            return False

    def harden(self):
        if self.expected_value:
            try:
                self.ssh.run('/sbin/service autofs start')
            except CommandExecutionException as err:
                if err.status_code == 1:
                    raise StopHardeningExecution("Service autofs is not "
                    "recognized and the hardening cannot proceed to start it.")
                raise
            report = "Service autofs started."
        else:
            try:
                self.ssh.run('/sbin/service autofs stop')
            except CommandExecutionException as err:
                if err.status_code == 1:
                    return "Service autofs not recognized, so it is not used."
                raise
            report = "Service autofs stopped."
        return report
