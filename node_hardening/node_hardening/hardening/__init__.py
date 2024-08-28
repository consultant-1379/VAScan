import inspect
import pkgutil
import sys
import time
import traceback

from node_hardening.ssh import SSHConnection
from node_hardening.utils import import_module
from node_hardening.hardening.base import BaseHardening, NullExpectedValue, \
    StopHardeningExecution


class HardeningProcessor(object):
    """ This is the hardening processor class that finds all the "hardeners"
    classes defined in the "hardening.<hardener_name>" package
    """

    def __init__(self, hardener_name, description, host, username, password,
            port=22, su_password=None, via_host=None, via_user=None,
            via_password=None):
        """ The constructor requires the node hardening description instance
        and the connection arguments as follows.
        :param description: a HardeningDescription instance
        :param host: host or ip address
        :param password: password of the user
        :param port: default is 22
        :param su_password: in case the user is not root, you must provide it.
        :param via_host: str, uses this host to connect to the "host" defined
        :param via_user: str, the username of the above host
        :param via_user: str, the username to be connected again
        :param via_password: str, the password of the above user
        :return: None
        """
        self.hardener_name = hardener_name
        self.description = description
        self.connection = SSHConnection(host, username, password, port,
                                        via_host, via_user, via_password)
        self.su_password = su_password
        self._len_msg = 0

    def start(self):
        """ Gets all methods of this class decorated by "section" and execute
        them.
        """
        t0 = time.time()
        with self.connection as ssh_client:
            for _, hardener_class in self._get_hardener_topics():
                ignored = self.process_hardener(hardener_class, ssh_client)
                if ignored:
                    self.description.ignored_topics.append(ignored)
        self.description.duration = time.time() - t0
        self.description.check_failed_topics()

    def process_hardener(self, hardener_class, ssh_client):
        """ Process a hardening procedure given a Hardener based class:
          1. Executes the check() method;
          2. If it raises NotImplementedError, then executes the report()
             method just to provide a report and return.
          3. If the returned value from the check() is equals
             as expected in the topic description, mark as success and return.
          4. Executes the harden() method in case the check above fails.
          5. Do the check() again and compare the value: fail or success.

        :param hardener_class: hardener class
        :param ssh_client: SSH client instance
        :return: None
        """
        hardener = hardener_class(self.description, ssh_client,
                                  self.su_password)
        topic = hardener.topic
        topic.hardener_implemented = True
        if isinstance(topic.expected_value, NullExpectedValue):
            ignored = (hardener.section, hardener_class.topic)
            msg = " Ignored %s: %s " % ignored
            sys.stdout.write(msg)
            sys.stdout.flush()
            self._len_msg = len(msg)
            self._print_status("IGNORED",
                          "not part of %s description" % self.description.name)
            return ignored
        msg = " Running %s: %s..." % (hardener.section, topic)
        self._len_msg = len(msg)
        sys.stdout.write(msg)
        sys.stdout.flush()

        # 1 or 2. check or report
        value = self._process(hardener.check, topic, hardener.report)
        topic.check_outputs = topic.outputs[:]
        topic.retrieved_value = value
        if topic.just_report:
            # report
            topic.report = value
            self._print_status('SUCCESS', 'just report')
        elif topic.retrieved_value is None:
            return
        elif value == topic.expected_value:
            # 3. checked
            topic.report = "Checked only, no hardening needed."
            self._print_status('SUCCESS: checked only, no hardening needed')
        else:
            # 4. do hardening as the checked value != expected
            topic.report = self._process(hardener.harden, topic)
            topic.harden_outputs = topic.outputs[len(topic.check_outputs):]
            if not topic.report:
                return
            # 5. check again
            value = self._process(hardener.check, topic)
            topic.double_check_outputs = topic.outputs[len(topic.check_outputs)
                                                  + len(topic.harden_outputs):]
            topic.retrieved_value = value
            if value == topic.expected_value:
                # checked again
                if topic.report:
                    self._print_status('SUCCESS: checked and hardened')
                else:
                    self._print_status('INCOMPLETE: no report provided')
                topic.checked_and_hardened = True
            else:
                # hardening failed
                diff =  "expected %s != %s" % (topic.expected_value, value)
                topic.error = "Check failed after harden process: %s" % diff
                self._print_status('FAILED', diff)

    def _process(self, method, topic, not_implemented_method=None):
        """ Executes the method and populate the topic attributes. 3 different
        exceptions are handled:
         1. NotImplementedError: executes the not_implemented_method and sets
                                 the topic.just_report attribute as True.
         2. StopHardeningExecution: sets the topic.error attribute with the
                                    error message.
         3. Exception: sets the topic.unhandled_error attribute with the
                       generic error message.
        :param method: method from a Hardener object (check, report or harden)
        :param topic: an instance of Topic class from the Hardener object.
        :param not_implemented_method: method from a Hardener object (report)
        :return: the value returned from the method() argument.
        """
        return_value = None
        try:
            return_value = method()
        except NotImplementedError as err:
            if not_implemented_method:
                if not_implemented_method.__name__ == 'report':
                    topic.just_report = True
                return self._process(not_implemented_method, topic)
            if method.__name__ == 'harden':
                topic.harden_case_not_implemented = str(err) or True
                self._print_status('FAILED', 'Harden case not implemented')
            else:
                self._print_status('INCOMPLETE')
        except StopHardeningExecution as err:
            topic.error = str(err)
            self._print_status('FAILED', topic.error)
        except Exception as err:
            ex_type, ex, tb = sys.exc_info()
            self._print_status('ERROR', "%s: %s" % (str(ex_type), str(err)))
            exc_list = traceback.format_exception(ex_type, ex, tb)
            tback = '\n'.join(exc_list)
            outs = ["%s\nSTATUS: %s\n%s" % o for o in topic.outputs]
            outs = '\n\n---------------------------------------\n\n'.join(outs)
            topic.unhandled_error = "TRACEBACK: \n\n%s\n\nOUTPUTS:\n\n%s" % \
                                    (tback, outs)
        return return_value

    def _print_status(self, status, desc=""):
        """ Helper method to print the status.
        :param status: str
        :param desc: str
        :return: None
        """
        white_space = " " * (70 - self._len_msg)
        desc = ": %s" % desc if desc else ""
        sys.stdout.write('%s%s%s\n' % (white_space, status, desc))
        sys.stdout.flush()

    def _get_hardener_topics(self):
        """ Returns a list of Hardener instances.
        :return: list
        """
        base_path = 'node_hardening.hardening.%s' % self.hardener_name
        package = import_module(base_path)
        hardeners = []
        for importer, name, is_pkg in pkgutil.iter_modules(package.__path__):
            if is_pkg:
                continue
            mod = import_module("%s.%s" % (base_path, name))
            for item_name, item in inspect.getmembers(mod):
                if not inspect.isclass(item):
                    continue
                if not issubclass(item, BaseHardening):
                    continue
                if item.section and item.topic:
                    hardeners.append(("%s.%s" % (name, item.topic), item))
        return hardeners

    def get_hardener_topic(self, name):
        hardener_topics = dict(self._get_hardener_topics())
        return hardener_topics[name]
