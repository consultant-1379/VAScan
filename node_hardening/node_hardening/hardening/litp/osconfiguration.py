from node_hardening.hardening.base import BaseHardening, CommandExecutionException, StopHardeningExecution
from node_hardening.parsers import PropertiesOutputParser, TwoColumnsKeyValueSumOutputParser, \
    ServicesStatusesParser, KeyValuesListOutputParser, NetstatTulpnOutputParser, \
    CrontabJobsPerUserParser
from node_hardening.report import Table


class OsConfiguration(BaseHardening):
    section = 'OsConfiguration'


class Processes(OsConfiguration):
    topic = 'processes'

    def report(self):
        """ Report the running processes and memory usage.
        """
        cmd = '/bin/ps -eo fname,%mem --sort -rss'
        out = self.ssh.run(cmd)
        out = '\n'.join(out.strip().splitlines()[1:])
        parser = TwoColumnsKeyValueSumOutputParser(out)
        data = parser.parse()
        return Table("Memory per process", data)


class RunningServices(OsConfiguration):
    topic = 'running_services'

    def report(self):
        """ Report the current services status in the system.
        """
        results = []
        cmd = '/sbin/service --status-all'
        out = self.ssh.run(cmd)
        parser = ServicesStatusesParser(out)
        all_services = parser.parse()
        running_services = [ serv for serv in all_services if all_services[serv] ]
        stopped_services = [ serv for serv in all_services if not all_services[serv] ]
        results.append({"Running Services": running_services})
        results.append({"Stopped Services": stopped_services})
        return results


class KnownServices(OsConfiguration):
    topic = 'known_services'

    def report(self):
        """ Report the know services in the system.
        """
        cmd = '/sbin/chkconfig --list'
        out = self.ssh.run(cmd)
        splited = out.split('\n\n')
        if len(splited) == 1:
            out1, out2 = splited[0], ""
        else:
            out1, out2 = splited
        parser = KeyValuesListOutputParser(out1)
        results = [Table('Services', parser.parse())]
        if out2:
            title2 = out2.splitlines()[0]
            out2 = '\n'.join(out2.splitlines()[1:])
            parser = KeyValuesListOutputParser(out2)
            results.append(Table(title2, parser.parse()))
        return results


class ServicesPorts(OsConfiguration):
    topic = 'services_ports'

    def report(self):
        """ Report the running services and ports used.
        """
        cmd = '/bin/netstat -tulpn'
        out = self.ssh.run(cmd)
        parser = NetstatTulpnOutputParser(out.strip())
        reports = [Table(t, d, True) for t, d in parser.parse().items()]
        return reports


class XWindowsUsed(OsConfiguration):
    topic = 'x_windows_used'

    def check(self):
        """ Check whether X-Windows is in use or not.
        """
        try:
            self.ssh.run('/sbin/pidof X')
            return True
        except CommandExecutionException:
            return False


class SystemCronJobs(OsConfiguration):
    topic = 'system_cron_jobs'

    def report(self):
        out = self.ssh.run('/bin/ls /etc/cron.*/*')
        return {'Cron jobs list' :out.split()}


class CronJobsPerUser(OsConfiguration):
    topic = 'cron_jobs_per_user'

    def report(self):
        cmd = 'for user in $(cut -f1 -d: /etc/passwd); do echo __$user; ' \
              'crontab -u $user -l; done'
        out = self.ssh.run(cmd, [1, 256])
        parser = CrontabJobsPerUserParser(out)
        return {'Cron jobs per user': parser.parse() or "no jobs per user."}


class SuidFiles(OsConfiguration):
    topic = 'suid_files'

    def report(self):
        report = dict()
        # Get the files with SUID set from the system
        scaned_suid_files = set()
        out = self.ssh.run('/bin/find / -perm -4000', [1, 256])
        for line in out.splitlines():
            if line.startswith('/bin/find: `/proc'):
                continue
            scaned_suid_files.add(line)

        # Based on the PO decision we wil just displays files with SUID.

        # # Calculate additional files with SUID set:
        # additional_suid_files = scaned_suid_files - set(expected_suid_files)
        # # If there are some file missing, this means we
        # # are having wrong baseline
        # missing_suid_files = set(expected_suid_files) - scaned_suid_files
        #
        # # 1 Report additional suid files, that were created unnecessary
        # #   during LITP installation
        # if additional_suid_files:
        #     report['Fail: Unnecessary additional ' \
        #            'SUID files detected'] = additional_suid_files
        #
        # # 2. Report missing suid files. That means the suid baseline is
        # #    not correct anymore and have to be regenerated.
        # if missing_suid_files:
        #     report['Fail: Missing SUID files - the SUID files ' \
        #            'baseline is not correct anymore'] = missing_suid_files
        #
        # if not additional_suid_files and not missing_suid_files:
        #     report['SUID Success'] = "There are no additional " \
        #                              "SUIDs files detected"
        report['SUID files'] = list(scaned_suid_files)
        return report



class SgidFiles(OsConfiguration):
    topic = 'sgid_files'

    def report(self):
        report = dict()
        # Get the files with SGID set from the system
        scaned_sgid_files = set()
        out = self.ssh.run('/bin/find / -perm -2000', [1, 256])
        for line in out.splitlines():
            if line.startswith('/bin/find: `/proc'):
                continue
            scaned_sgid_files.add(line)

        # Based on the PO decision we wil just displays files with SGID.

        # # Calculate additional files with SGID set:
        # additional_sgid_files = scaned_sgid_files - set(expected_sgid_files)
        # # If there are some file missing, this means we
        # # are having wrong baseline
        # missing_sgid_files = set(expected_sgid_files) - scaned_sgid_files
        #
        # # 1 Report additional sgid files, that were created unnecessary
        # #   during LITP installation
        # if additional_sgid_files:
        #     report['Fail: Unnecessary additional ' \
        #            'SGID files detected'] = additional_sgid_files
        #
        # # 2. Report missing sgid files. That means the sgid baseline is
        # #    not correct anymore and have to be regenerated.
        # if missing_sgid_files:
        #     report['Fail: Missing SGID files - the SGID files ' \
        #            'baseline is not correct anymore'] = missing_sgid_files
        #
        # if not additional_sgid_files and not missing_sgid_files:
        #     report['SGID Success'] = "There are no additional " \
        #                              "SGIDs files detected"
        report['SGID files'] = list(scaned_sgid_files)
        return report
