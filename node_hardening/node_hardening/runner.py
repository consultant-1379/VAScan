import cPickle
from datetime import datetime

from node_hardening.utils import import_module
from node_hardening.basedescription import HardeningDescription, \
                                           FailedOrIncompleteTopicsException
from node_hardening.hardening import HardeningProcessor
from node_hardening.report import ReportBuilder


def get_description_class(description_module):
    """ From a description module name, gets the actual description class.
    :param description_module: str, e.g.: module.sub_module
    :return: HardeningDescription based class
    """
    module_name = "node_hardening.descriptions.%s" % description_module
    module = import_module(module_name)
    for attr in dir(module):
        value = getattr(module, attr, None)
        try:
            if value != HardeningDescription and \
               issubclass(value, HardeningDescription) and \
               hasattr(value, '__module__') and \
               value.__module__ == module_name:
                return value
        except TypeError:
            pass
    raise Exception('No module %s found' % module_name)


def run_node_hardening(description_module, host, user, password, port=22,
        su_password=None, via_host=None, via_user=None,
        via_password=None, topic=None, mock_report=False,
                       report_filename=None):
    """ From a description_module and connection arguments, runs all the node
    hardening procedure based on the sections and topics of the description.

    It returns a tuple of (bool, str):
     - bool: whether the execution is succeeded or not;
     - str: the report filename.

    :param description_module: str, e.g.: module.sub_module
    :param host: str, ip or host name of the machine to be hardened
    :param user: str, username
    :param password: str
    :param port: int, ssh port, default is 22
    :param su_password: str, in case the user is not root
    :param via_host: str, uses this host to connect to the "host" defined above
    :param via_user: str, the username of the above host
    :param via_password: str, the password of the above user
    :param topic: str, the name of the topic to be executed
    :param mock_report: bool
    :param report_filename: str, full path to generated report
    :return: tuple (bool, str) => (success or not, report filename)
    """

    failed_topics = []
    incomplete_topics = []
    no_hardener_implemented = []
    description = None
    if not mock_report:
        hardener_name = description_module.split('.')[0]
        DescriptionClass = get_description_class(description_module)
        description = DescriptionClass(host)
        h = HardeningProcessor(hardener_name, description, host, user,
                password, port, su_password, via_host,
                               via_user, via_password)
        if topic:
            try:
                hclass = h.get_hardener_topic(topic)
                print(" Running the topic: %s" % topic)
            except AttributeError:
                print " Topic %s doesn't exist." % topic
                exit(1)
            h.process_hardener(hclass)
            try:
                description.check_failed_topics()
            except FailedOrIncompleteTopicsException as err:
                failed_topics = err.failed_topics
                incomplete_topics = err.incomplete_topics
                no_hardener_implemented = err.no_hardener_implemented_topics
        else:
            try:
                h.start()
            except FailedOrIncompleteTopicsException as err:
                failed_topics = err.failed_topics
                incomplete_topics = err.incomplete_topics
                no_hardener_implemented = err.no_hardener_implemented_topics

        #from copy import deepcopy
        #with open('last_report.pickle', 'w') as f:
        #    cPickle.dump(deepcopy(h.description), f)
        report = ReportBuilder(h.description)
    else:
        with open('last_report.pickle') as f:
            description = cPickle.load(f)
        report = ReportBuilder(description)
    text = report.to_text()
    now = datetime.now().isoformat()

    if not report_filename:
        report_filename = 'report_for_%s_description_%s_%s.html' % (
            description.name,
            host, now
        )

    with open(report_filename, 'w') as report_file:
        report_file.write(report.to_html())

    report_msg = "The report has been saved in the file %s" % report_filename

    print
    print "#" * 77
    print
    if topic:
        if failed_topics:
            print
            print " The following topics failed:"
            for topic in failed_topics:
                print " - %s: %s" % (topic, topic.error or
                                     topic.unhandled_error)
        else:
            print " SUCCESS!"
            print
            print report_msg
            print
    else:
        if failed_topics or incomplete_topics or no_hardener_implemented:
            print " !!!!!! FAILED !!!!!!"
            print
            if incomplete_topics:
                print " The following topics are incomplete:"
                for topic in incomplete_topics:
                    print " - %s" % topic
            if failed_topics:
                print
                print " The following topics failed:"
                for topic in failed_topics:
                    print " - %s: %s" % (topic, topic.error or
                                         topic.unhandled_error)
            if no_hardener_implemented:
                print
                print " The following topics were not executed because no " \
                      "Hardener class seems to be created:"
                for topic in no_hardener_implemented:
                    print " - %s" % topic

            print
            print
            print report_msg
            print
            return False, report_filename
        else:
            print " SUCCESS!"
            print
            print report_msg
            print
    return True, report_filename
