from node_hardening.hardening.base import BaseHardening, CommandExecutionException, StopHardeningExecution
from node_hardening.parsers import PropertiesOutputParser


class FirewallConfiguration(BaseHardening):
    section = 'FirewallConfiguration'

    def _is_plugin_installed(self):
        is_installed = False
        out = self.ssh.run('rpm -qa | grep firewall', silent_fail_if=[1])
        for line in out.splitlines():
            if line.startswith("ERIClitplinuxfirewall"):
                is_installed = True
                break
        return is_installed


class PluginInstalled(FirewallConfiguration):
    topic = 'plugin_installed'

    def check(self):
        return self._is_plugin_installed()


class PluginEnabled(FirewallConfiguration):
    topic = 'plugin_enabled'

    def check(self):
        is_installed = self._is_plugin_installed()
        if not is_installed:
            return is_installed
        cmd = 'litp show -p /ms/configs/fw_config_init/rules/fw_icmp'
        output = self.ssh.run(cmd)
        parser = PropertiesOutputParser(output)
        data = parser.parse()['state']
        is_applied = data == 'Applied'
        return is_applied


class TftpPortDisabled(FirewallConfiguration):
    topic = 'tftp_port_disabled'

    def is_tftp_rule_applied(self, path):
        cluster_firewalls = self.litp.get_model_items_by_type(path,
                                                              "firewall-rule")
        for item in cluster_firewalls:
            name = item['properties']['name']['value']
            if "tftp" in name and item['state'] == "Applied":
                return True
        return False

    def check(self):
        cluster_tftp = self.is_tftp_rule_applied('/deployments')
        ms_tftp = self.is_tftp_rule_applied('/ms')
        return cluster_tftp and ms_tftp

    def harden(self):
        should_be_disabled = self.expected_value
        if not should_be_disabled:
            raise NotImplementedError("The case of enabling tftp port is not "
                                      "implemented")
        report = None
        try:
            plan = self.litp.get_plan()
            if plan['status'] == 'Running':
                raise StopHardeningExecution("Configure tftp firewall plan "
                     "cannot execute as a plan already exists in status: %s" %
                     plan['status'])
        except CommandExecutionException as err:
            if 'Plan does not exist' not in str(err):
                raise

        ms_firewalls = self.litp.get_model_items_by_type("/ms", "firewall-rule")
        cluster_firewalls = self.litp.get_model_items_by_type("/deployments",
                                                              "firewall-rule")
        ms_fw_path = ms_firewalls[0]['vpath'].rsplit('/', 1)[0]
        cluster_fw_path = cluster_firewalls[0]['vpath'].rsplit('/', 1)[0]

        cluster_tftp = self.is_tftp_rule_applied('/deployments')
        ms_tftp = self.is_tftp_rule_applied('/ms')

        if not ms_tftp:
            self.litp.create_item('firewall-rule', '%s/fw_tftp' % ms_fw_path,
                                  name="\"015 tftp\"", dport="69")

        if not cluster_tftp:
            self.litp.create_item('firewall-rule',
                                  '%s/fw_tftp' % cluster_fw_path,
                                  name="\"015 tftp\"", dport="69")

        if not cluster_tftp or not ms_tftp:
            self.litp.create_plan()
            self.litp.run_plan()
            status = self.litp.wait_plan()
            if status == 'Failed':
                raise StopHardeningExecution("Configure tftp firewall "
                                             "plan failed")
            report = "ftp ports disabled on MS and nodes."

        return report
