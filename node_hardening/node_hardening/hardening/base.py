import re
import time

from node_hardening.section import NullExpectedValue, CommandExecutionException
from node_hardening.utils import camelcase_to_underscore
from node_hardening.parsers import LitpModelItemOutputParser, LitpPlanOutputParser


class StopHardeningExecution(Exception):
    """ This exception may be raise in the node hardening process anytime
    there's no possibility to do any action for the node hardening. The
    fault will be logged/flagged in the report.
    """


class SshRunner(object):
    """ This class just the ssh runner for each topic, that also includes the
    history of outputs coming from the ssh executions. This "outputs" list
    history will be used later on in the ReportBuilder.
    """

    def __init__(self, ssh, outputs, su_password=None):
        """ It requires the ssh instance of SshScpClient and the outputs list.
        """
        self._ssh = ssh
        self._su_password = su_password
        self.outputs = outputs

    def run(self, cmd, silent_fail_if=None, populate_output=True,
            expects=None):
        """ This method executes a command and returns the output. In case
        of failure (status code != 0), it raises the CommandExecutionException.

        The silent_fail_if argument requires a list of status codes. If the
        status code is in the list, the exception is not raised.

        The expects argument requires a list of strings. It's useful when the
        shell prompts an expected input. So each string of the list will be
        input after the command execution.

        :param cmd: str
        :param silent_fail_if: list of status codes to not raise exception
        :param populate_output: bool, to populate the output history
        :param expects: list of inputs in case the shell prompts
        :return: str, the output coming from the execution of the cmd
        """
        self._ssh.connect()
        code, out, err = self._ssh.run(cmd, su=self._su_password,
                                       expects=expects)
        out = out + err
        silent_fail_if = silent_fail_if or []
        if populate_output:
            self.outputs.append((cmd, code, out))
        if code != 0 and code not in silent_fail_if:
            msg = "cmd: %s, status code: %s, output: %s" % (cmd, code, out)
            raise CommandExecutionException(msg, out, code)
        # takes password warning messages out from the output.
        out = '\n'.join([l for l in out.splitlines()
               if not l.startswith('Warning: your password will expire in ')])
        if out.strip().startswith('Password: '):
            out = '\n'.join(out.splitlines()[1:])
        return out

    def read_file(self, path):
        """ Reads a remote file given a path.
        """
        return self.run('cat "%s"' % path)

    def write_file(self, path, content):
        """ Writes a content in a remote file given a path.
        """
        for line in content.splitlines():
            self.run("echo %s >> %s".format(line, path), populate_output=False)

    def insert_line_in_file(self, path, line, regex, after=True):
        """ Inserts a line in a file after or before a specific line defined on
        the regex argument.
        NOTE: this method uses "sed" and regular expression are a bit limited.
        Some shortcuts doesn't work quite well, e.g.: use [0-9] instead of \d.
        """
        if after:
            self.run("sed -i -r '/%s/a %s' %s" % (regex, line, path))
        else:
            self.run("sed -i -r '/%s/i %s' %s" % (regex, line, path))

    def replace_line_in_file(self, path, line, regex):
        """ Replaces a specific line defined on the regex argument in a file.
        NOTE: this method uses "sed" and regular expression are a bit limited.
        Some shortcuts doesn't work quite well, e.g.: use [0-9] instead of \d.
        """
        self.run("sed -i -r 's/%s/%s/g' %s" % (regex, line, path))

    def remove_line_from_file(self, path, regex):
        """ Removes a specific line defined on the regex argument in a file.
        NOTE: this method uses "sed" and regular expression are a bit limited.
        Some shortcuts doesn't work quite well, e.g.: use [0-9] instead of \d.
        """
        self.run("sed -i -r '/%s/d' %s" % (regex, path))



def wait(func):
    """ This decorator is used in the LitpHelper class below to just wait
    litp plan to run in case it is running, before execute the method.
    """
    def wait(self, *args, **kwargs):
        if not self.is_plan_finished():
            self.wait_plan()
        return func(self, *args, **kwargs)
    return wait


class LitpHelper(object):

    plan_not_exists_regex = re.compile(r'.*InvalidLocationError\s+Plan\s+does'
                                       r'\s+not\s+exist.*')

    def __init__(self, ssh_runner):
        self.ssh = ssh_runner

    def get_clusters(self):
        base = '/deployments/d1/clusters'
        out = self.ssh.run("/usr/bin/litp show -p %s" % base)
        parser = LitpModelItemOutputParser(out)
        clusters = []
        for child in parser.parse()['children']:
            clusters.append(self.get_model_item("%s%s" % (base, child)))
        return clusters

    def get_model_item(self, path):
        out = self.ssh.run("/usr/bin/litp show -p %s" % path)
        parser = LitpModelItemOutputParser(out)
        return parser.parse()

    def get_model_items_by_type(self, path, item_type):
        out = self.ssh.run("/usr/bin/litp show -r -p %s" % path)
        items = out.split("\n\n")
        model_items = []
        for item in items:
            parser = LitpModelItemOutputParser(item)
            model_item = parser.parse()
            if model_item['type'] == item_type:
                model_items.append(model_item)
        return model_items

    @wait
    def remove_item(self, path):
        self.ssh.run('/usr/bin/litp remove -p %s' % path)

    @wait
    def create_item(self, item_type, path, **kwargs):
        cmd = '/usr/bin/litp create -t %s -p %s' % (item_type, path)
        if kwargs:
            pairs = ["%s=%s" % (k, v) for k, v in kwargs.items()]
            cmd = "%s -o %s" % (cmd, ' '.join(pairs))
        self.ssh.run(cmd)

    def get_plan(self):
        out = self.ssh.run("/usr/bin/litp show_plan")
        parser = LitpPlanOutputParser(out)
        return parser.parse()

    def is_plan_finished(self):
        try:
            plan = self.get_plan()
        except CommandExecutionException as err:
            # status 1 usually means that the plan doesn't exist
            if err.status_code == 1:
                last_line = [i for i in
                             err.output.splitlines() if i.strip()][-1]
                # just double checking below though the regex
                if self.plan_not_exists_regex.match(last_line):
                    # it means that there's no plan running, so return True
                    return True
            # otherwise fail
            raise
        return plan['status'] in ['success', 'failed', 'stopped']

    @wait
    def create_plan(self):
        self.ssh.run("/usr/bin/litp create_plan")

    def run_plan(self):
        self.ssh.run("/usr/bin/litp run_plan")

    def wait_plan(self, timeout=1800, sec_increment=20):
        seconds_count = sec_increment
        finished_statuses = ["Failed", "Successful"]
        while True:
            time.sleep(sec_increment)
            plan = self.get_plan()
            status = plan['status']
            seconds_count += sec_increment
            if status in finished_statuses:
                return status
            if seconds_count > timeout:
                raise StopHardeningExecution("LITP run plan timeout reached.")


class BaseHardening(object):
    section = None
    topic = None

    def __init__(self, description, ssh, su_password=None):
        section = getattr(description, camelcase_to_underscore(self.section))
        self.topic = getattr(section, self.topic)
        self.ssh = SshRunner(ssh, self.topic.outputs, su_password)
        self.description = description
        self.litp = LitpHelper(self.ssh)

    def check(self):
        raise NotImplementedError

    def harden(self):
        raise NotImplementedError

    def report(self):
        raise NotImplementedError

    @property
    def expected_value(self):
        return self.topic.expected_value

    def all_exclusive(self, alist):
        if all(alist):
            return True
        elif not any(alist):
            return False
        else:
            return None

    def _remove_package(self, package):
        try:
            self.ssh.run("/bin/rpm -q %s" % package)
        except CommandExecutionException as err:
            if err.status_code == 1:
                return "Package %s is not installed on system." % package
        try:
            self.ssh.run('/usr/bin/yum -y remove %s' % package)
        except CommandExecutionException as err:
            raise StopHardeningExecution('Failed to remove the package '
                                         '%s: %s' % (package, err))
        return "Package %s has been remove from system." % package
