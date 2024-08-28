import re
import sys

from node_hardening.hardening.base import BaseHardening, CommandExecutionException, StopHardeningExecution


class SystemAccessControl(BaseHardening):
    section = 'SystemAccessControl'


class AccountLocking(SystemAccessControl):
    topic = 'account_locking'
    regex1 = re.compile(r'\s*auth\s+required\s+pam_faillock\.so\s+preauth'
                      r'\s+silent\s+audit\s+deny=(\d+)\s+unlock_time=(\d+)\s*')
    regex2 = re.compile(r'\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+'
                       r'authfail\s+audit\s+deny=(\d+)\s+unlock_time=(\d+)\s*')
    pam_files = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]

    def _get_deny_unlock_time(self, pam_file):
        content = self.ssh.run('cat %s' % pam_file)
        match1 = match2 = None
        for line in content.splitlines():
            if not match1:
                match1 = self.regex1.match(line)
            if not match2:
                match2 = self.regex2.match(line)
        if not match1 or not match2:
            return None, None
        tuple1 = tuple(map(lambda x: int(x), match1.groups()))
        tuple2 = tuple(map(lambda x: int(x), match2.groups()))
        if tuple1 != tuple2:
            return None, None
        return tuple1

    def check(self):
        deny_unlock = [self._get_deny_unlock_time(p) for p in self.pam_files]
        if len(set(deny_unlock)) == 1:
            return deny_unlock[0]


    def harden(self):
        expected_account_locking = self.expected_value
        report = {'Account Locking': []}

        for pam_file in self.pam_files:
            deny_unlock = self._get_deny_unlock_time(pam_file)

            if deny_unlock == expected_account_locking:
                msg = "File {0} already updated with pam_faillock account " \
                      "locking configuration".format(pam_file)
                report['Account Locking'].append(msg)
                continue
            updated_auth = self._add_faillock_pam_configuration(
                                                pam_file,
                                                *expected_account_locking)

            self.ssh.run('cp {0} {0}.bkp'.format(pam_file))
            print "\nUpdating {0} file".format(pam_file)
            for line in updated_auth:
                sys.stdout.write('. ')
                sys.stdout.flush()
                # Fixme: It will be good to have some other method to copy file
                # Fixme: on the node, rather then copy line by line :(
                self.ssh.run("echo '{0}' >> {1}.new".format(line, pam_file),
                             populate_output=False)
            self.ssh.run('mv {0}.new {0}'.format(pam_file))
            msg = "File {0} updated with pam_faillock account " \
                  "locking configuration".format(pam_file)
            print '\n' + msg
            report['Account Locking'].append(msg)
        return report

    def _add_faillock_pam_configuration(self, pam_file, deny, unlock_time):
        """ Helper function to update PAM files with pam_faillock
            The pam_faillock auth lines have to placed in specific place in
            the pam configuration files, please refer the LITP hardening doc.
        """
        content = self.ssh.run('cat %s' % pam_file)
        updated_content = []
        count = 0
        auth1_faillock = "auth        required      pam_faillock.so preauth " \
                         "silent audit deny={0} unlock_time={1}".format(
            deny,
            unlock_time
        )
        auth2_faillock = "auth        [default=die] pam_faillock.so " \
                         "authfail audit deny={0} unlock_time={1}".format(
            deny,
            unlock_time
        )

        for line in content.splitlines():
            if self.regex1.match(line) or self.regex2.match(line):
                continue
            if re.search('auth\s+sufficient\s+pam_unix.so', line):
                updated_content.append(auth1_faillock)
                updated_content.append(line)
                updated_content.append(auth2_faillock)
                count += 1
                continue
            updated_content.append(line)

        if count == 1:
            return updated_content
        else:
            raise StopHardeningExecution("Can't update pam.d files with "
                                         "pam_faillock configuration changes")

class LoginBannerPresent(SystemAccessControl):
    topic = 'login_banner_present'

    banner_file = '/etc/issue'
    banner_phrase = "This system is for authorised use only. By using this " \
                    "system you consent to monitoring and data collection."
    banner = "###########  WARNING  ############\n\n%s\n\n" \
             "##################################" % banner_phrase

    def check(self):
        out = self.ssh.run('cat %s' % self.banner_file)
        return self.banner_phrase in out

    def harden(self):
        should_be_present = self.expected_value
        if should_be_present:
            self.ssh.run(" > %s" % self.banner_file)
            self.ssh.run("echo '%s' >> %s" % (self.banner, self.banner_file))
            report = "Cleared the %s file and added the new banner." % \
                     self.banner_file
        else:
            self.ssh.run(" > %s" % self.banner_file)
            report = "A login banner should not be present, cleared the " \
                     "file %s." % self.banner_file
        return report
