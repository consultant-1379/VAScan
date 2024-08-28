import re
from node_hardening.hardening.base import BaseHardening


class PasswordEncryption(BaseHardening):
    section = 'PasswordEncryption'


class GrubPasswordEncrypted(PasswordEncryption):
    topic = 'grub_password_encrypted'

    timeout_regex_str = 'timeout=[0-9]+'
    password_line_regex_str = r'password \-\-md5 .*'
    password_line_regex = re.compile(password_line_regex_str)
    grub_conf = '/boot/grub/grub.conf'

    def check(self):
        is_encrypted = False
        for line in self.ssh.read_file(self.grub_conf).splitlines():
            if self.password_line_regex.match(line.strip()):
                is_encrypted = True
                break
        return is_encrypted

    def harden(self):
        pwd = self.description.grub_password
        if self.expected_value:
            out = self.ssh.run('/sbin/grub-md5-crypt', expects=[pwd, pwd])
            password_hash = out.splitlines()[-1]
            new_line = "password --md5 %s" % password_hash
            self.ssh.insert_line_in_file(self.grub_conf, new_line,
                                         self.timeout_regex_str)
            report = "Grub password encrypted."
        else:
            self.ssh.remove_line_from_file(self.grub_conf,
                                           self.password_line_regex_str)
            report = "Grub password was encrypted, but removed " \
                     "from the %s file afterwards." % self.grub_conf
        return report

