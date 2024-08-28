from nessusapi import NessusApi, NessusApiError
import sys
import os
import yaml
import argparse
import time


class NessusSettings(object):

    def __init__(self, filename):
        self.settings = yaml.safe_load(open(filename))

    def get_access_key(self):
        return self.settings['ACCESS_KEY']

    def get_secret_key(self):
        return self.settings['SECRET_KEY']

    def get_url(self):
        return self.settings['API_URL']


def process_args():

    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', '-p', required=True,
                        help='The Nessus policy used for scanning')
    parser.add_argument('--target', '-t', required=True,
                        help='Target system that will '
                             'be scan for vulnerabilities')
    parser.add_argument('--settings', '-s', required=True,
                        dest='settings_filename', help='Nessus settings file')
    parser.add_argument('--report', '-r', required=True,
                        dest='report_filename', help='Nessus report file name')
    parser.add_argument('--format', '-f', default='pdf',
                        choices=["nessus", "csv", "html", "pdf"],
                        help='The Scan report format')
    return parser.parse_args()


def get_args_from_setting_file(args):
    try:
        settings = NessusSettings(args.settings_filename)
    except IOError:
        template_filename = "settings_template.yaml"
        print "\nERROR: Nessus setting files '{0}' don't exist or you don't " \
              "have permission to read it".format(args.settings_filename)
        print "Please use settings_template.yaml file as template: {1}".format(
            template_filename,
            os.path.abspath(template_filename)
        )
        sys.exit(1)
    try:
        url = settings.get_url()
        access_key = settings.get_access_key()
        secret_key = settings.get_secret_key()
    except KeyError as err:
        print "\nERROR: Parameter {0} not defined" \
              " in Nessus settings file".format(err.args[0])
        sys.exit(2)
    return url, access_key, secret_key


def get_policy_id(api, policy_name):
    try:
        policy_id = api.policies.get_policy_id(policy_name)
    except NessusApiError:
        print "\nERROR: Policy {0} not found on Nessus".format(policy_name)
        policies = api.policies.get_policy_names()
        if policies:
            print "The current defined policies on Nessus are: %s." % \
                  ", ".join(policies)
        else:
            print "No policies are defined on Nessus."
        sys.exit(3)
    return policy_id

if __name__ == "__main__":

    args = process_args()
    url, access_key, secret_key = get_args_from_setting_file(args)
    api = NessusApi(url, access_key, secret_key)
    policy_id = get_policy_id(api, args.policy)

    s_name = '{0} scan for {1} at {2}'.format(
        args.policy, args.target, time.strftime("%d/%m/%Y %H:%M")
    )
    scan = api.scans.create(name=s_name, policy_id=policy_id, targets=args.target)
    scan_id = scan['scan']['id']
    print "\nCreating scan using policy: {0} for target: {1}" \
          "\nScanning...".format(args.policy, args.target)
    api.scans.launch_and_wait(scan_id)
    print "Scan report exported to file: {0}".format(args.report_filename)
    file_content = api.scans.export_and_download(scan_id,
                                                 export_format=args.format)
    with open(args.report_filename, 'wb') as fd:
        fd.write(file_content)
