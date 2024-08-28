import re
from node_hardening.hardening.base import BaseHardening, CommandExecutionException, StopHardeningExecution
from node_hardening.parsers import RealUsersParser, PropertiesOutputParser


class LoginControl(BaseHardening):
    section = 'LoginControl'

    def _get_users(self):
        cmd = "cat /etc/passwd"
        passwd = self.ssh.run(cmd)
        parser = RealUsersParser(passwd)
        return parser.parse() + ['root']

    def _get_users_to_change(self):
        expected_password_age = self.expected_value
        all_users = self._get_users()
        # Check what is the current MAX password age for each user
        users = []
        for user in all_users:
            cmd = 'chage -l {0}'.format(user)
            out = self.ssh.run(cmd)
            parser = PropertiesOutputParser(out)
            data = parser.parse()
            max_age = data['Maximum number of days between password change']
            if expected_password_age != int(max_age):
                users.append((user, max_age))
        return users


class PasswordAge(LoginControl):
    topic = 'password_age'

    def check(self):
        users_ages = self._get_users_to_change()
        if users_ages:
            return users_ages
        else:
            return self.expected_value

    def harden(self):
        report = []
        expected_password_age = self.expected_value
        for user, _ in self._get_users_to_change():
            # We are updating the last password change to current day
            # This is OK for the automatic scan but it SHOULD NOT be done
            # for the real hardening product.
            cmd = 'chage -d $(date +%Y-%m-%d) -M {0} {1}'.format(
                expected_password_age, user)
            self.ssh.run(cmd)
            report.append(user)
        return "Changed users: %s." % ', '.join(report)


class IdleTimeout(LoginControl):
    topic = 'idle_timeout'

    def check(self):
        filename = "/etc/profile.d/os-security.sh"
        cmd = "cat {0} || echo 'No File'".format(filename)
        out = self.ssh.run(cmd)
        match = re.search(r'TMOUT=(\d+)', out)
        return int(match.group(1)) if match else 0

    def harden(self):
        expected_idle_timeout = self.expected_value
        filename = "/etc/profile.d/os-security.sh"
        cmd = "cat {0} || echo 'No File'".format(filename)
        out = self.ssh.run(cmd)
        match = re.search(r'TMOUT=(\d+)', out)
        if not match:
            if re.search('No File', out):
                self.ssh.run("echo 'readonly TMOUT={0}' >> {1}".format(
                    expected_idle_timeout,
                    filename
                ))
                self.ssh.run("chmod +x {0}".format(filename))
                report = "File {0} created with idle timeout: {1}".format(
                    filename,
                    expected_idle_timeout
                )
            else:
                raise StopHardeningExecution("Can't update file: {0} with "
                                             "idle timeout {1}".format(
                    filename,
                    expected_idle_timeout
                ))
        else:
            self.ssh.run("sed -i.bkp 's/{0}/{1}/g' {2}".format(
                    match.group(1),
                    expected_idle_timeout,
                    filename
                ))
            report = "File {0} updated with idle timeout: {1}".format(
                filename, expected_idle_timeout)
        return report
