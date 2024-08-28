import argparse
import sys
from commands import getstatusoutput

from node_hardening.runner import run_node_hardening


def get_arguments():

    parser = argparse.ArgumentParser(description='Do the node hardening on a '
                            'host based on a node hardening description.')

    parser.add_argument('--description', '-d', dest='description',
                        help='The module containing the description, e.g:'
                             '"litp.ms", "litp.node", "litp.kvm".')
    parser.add_argument('--topic', '-t', dest='topic',
                        help='You can specify a single topic to run.',
                        required=False)
    parser.add_argument('--host', '-H', dest='host',
                        help='The host that should be connected to to execute '
                             'the node hardening')
    parser.add_argument('--user', '-u', dest='user', help='The username')
    parser.add_argument('--password', '-p', dest='password',
                        help='The password')
    parser.add_argument('--port', '-P', dest='port', default=22,
                        help='The host port')
    parser.add_argument('--su-password', '-s', dest='su_password',
                        help='The su password')
    parser.add_argument('--via-host', '-o', dest='via_host',
                        help='Connects to the host defined in the argument'
                             '"host" via this host --via-host.')
    parser.add_argument('--via-user', '-e', dest='via_user',
                        help='The username of the above host')
    parser.add_argument('--via-password', '-a', dest='via_password',
                        help='The password of the above user')
    parser.add_argument('--view-report', '-v', dest='view_report',
                        required=False, action='store_true',
                        help="Open a new tab in the Chrome browser with the "
                             "report.")

    parser.add_argument('--mock-report', '-m', dest='mock_report',
                        required=False, action='store_true',
                        help="It doesn't run the hardening, just generate a "
                             "report based on the previous data.")
    parser.add_argument('--report-filename', '-r', dest='report_filename',
                        required=False, help="The filename of the hardening "
                                             "report in html format")

    args = parser.parse_args()
    if not all([args.description, args.host, args.user, args.password]):
        print
        parser.print_help()
        print
        sys.exit(1)
    return args


if __name__ == '__main__':
    args = get_arguments()
    success, filename = run_node_hardening(args.description, args.host,
        args.user, args.password, args.port, args.su_password,
        args.via_host, args.via_user, args.via_password, args.topic,
        args.mock_report, args.report_filename)
    if args.view_report:
        browsers = ['/usr/bin/sensible-browser', '/usr/bin/google-chrome',
                    '/usr/bin/firefox']
        code = out = None
        for browser in browsers:
            code, out = getstatusoutput('%s "%s"' % (browser, filename))
            if code == 0:
                break
        if code != 0:
            print out
    if not success:
        sys.exit(244)
