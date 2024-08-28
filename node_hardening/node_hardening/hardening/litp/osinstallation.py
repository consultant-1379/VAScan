from node_hardening.hardening.base import BaseHardening, CommandExecutionException, StopHardeningExecution
from node_hardening.parsers import PropertiesOutputParser


class OsInstallation(BaseHardening):
    section = 'OsInstallation'

    def get_selinux_properties(self):
        out = self.ssh.run('/usr/sbin/sestatus')
        parser = PropertiesOutputParser(out)
        return parser.parse()


class Packages(OsInstallation):
    topic = 'packages'

    def report(self):
        # 1 and 2. check un/necessary packages
        out = self.ssh.run('/bin/rpm -qa')
        #existing_packages = set(out.splitlines())
        #expected_packages = set(expected_value)
        #missing_packages = expected_packages - existing_packages
        #unnecessary_packages = existing_packages - expected_packages
        #report = dict()
        # 1 report necessary packages
        #if missing_packages:
        #    report['Missing Packages'] = list(missing_packages)

        # 2. report unnecessary packages
        #if unnecessary_packages:
        #    report['Unnecessary Packages'] = list(unnecessary_packages)

        #if not missing_packages and not unnecessary_packages:
        #    report['Packages'] = "All packages are installed and there's
        #                         "no unnecessary packages installed too."
        return {'Installed Packages': out.splitlines()}


class UnwantedPackages(OsInstallation):
    topic = 'unwanted_packages'

    def _get_cluster_services(self):
        services = []
        for cluster in self.litp.get_clusters():
            servs = self.litp.get_model_item("%s/%s" % (cluster['vpath'],
                                                       'services'))
            for service in servs.get('children', []):
                path = "%s/services/%s/applications" % (cluster['vpath'],
                                                        service.strip('/'))
                apps = self.litp.get_model_item(path)
                services.append((path, map(lambda x: x.strip('/'),
                                           apps.get('children', []))))
                path = "%s/services/%s/runtimes" % (cluster['vpath'],
                                                    service.strip('/'))
                runts = self.litp.get_model_item(path)
                services.append((path, map(lambda x: x.strip('/'),
                                            runts.get('children', []))))
        return services

    def check(self):
        services = set(reduce(lambda a, b: a + b,
                              [i[1] for i in self._get_cluster_services()]))
        return list(set(self.expected_value) - services)

    def harden(self):
        for_removal = []
        for path, services in self._get_cluster_services():
            for item in services:
                item = item.strip('/')
                if item in self.expected_value:
                    for_removal.append(item)
                    path_to_remove = '/'.join(path.split('/')[:-1])
                    self.litp.remove_item(path_to_remove)
        self.litp.create_plan()
        self.litp.run_plan()
        self.litp.wait_plan(sec_increment=30)
        return "The following services/packages were removed successfully: " \
               "%s" % ', '.join(for_removal)


class SeLinuxEnabled(OsInstallation):
    topic = 'selinux_enabled'

    def check(self):
        status = self.get_selinux_properties().get('SELinux status')
        return status == 'enabled'

    def harden(self):
        if self.expected_value:
            # can't do it without reboot
            raise NotImplementedError("The case of enabling selinux must be "
                                      "implemented.")
        else:
            raise NotImplementedError("The case of disabling selinux must be "
                                      "implemented.")


class SeLinuxEnforced(OsInstallation):
    topic = 'selinux_enforced'

    def check(self):
        mode = self.get_selinux_properties().get('Current mode')
        return mode == 'enforcing'

    def harden(self):
        if self.expected_value:
            self.ssh.run('echo 1 >/selinux/enforce')
            return "selinux has been enforced."
        else:
            self.ssh.run('echo 0 >/selinux/enforce')
            return "selinux enforce has been removed."
