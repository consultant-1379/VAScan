import re
from node_hardening.hardening.base import BaseHardening, CommandExecutionException, StopHardeningExecution


class VirtualMachineHardening(BaseHardening):
    section = 'VirtualMachineHardening'


class RootSshAccess(VirtualMachineHardening):
    topic = 'root_ssh_access'

    cmd = "grep '^PermitRootLogin' /etc/ssh/sshd_config || echo 'Not Found'"

    def check(self):
        out = self.ssh.run(self.cmd)
        return bool(re.search(r'yes', out))

    def harden(self):
        out = self.ssh.run(self.cmd)
        if self.expected_value:
            if re.search('no', out):
                # Change Permit Root login to Yes and restart sshd service
                self.ssh.run("sed -i.bkp 's/^PermitRootLogin no/"
                        "PermitRootLogin yes/g' /etc/ssh/sshd_config")
                self.ssh.run("nohup /sbin/service sshd restart")
                report = "Permit root login - Changed to Yes"
            else:
                report = "Permit root login - No changes require"
        else:
            if re.search(r'Not Found', out):
                # Set Permit Root login to No and restart sshd service
                self.ssh.run("echo 'PermitRootLogin no' >> /etc/ssh/sshd_config")
                self.ssh.run("nohup /sbin/service sshd restart")
                report = "Permit root login - Set to No"
            elif re.search(r'yes', out):
                # Change Permit Root login to No and restart sshd service
                self.ssh.run("sed -i.bkp 's/^PermitRootLogin yes/"
                        "PermitRootLogin no/g' /etc/ssh/sshd_config")
                self.ssh.run("nohup /sbin/service sshd restart")
                report = "Permit root login - Changed to No"
        return report
