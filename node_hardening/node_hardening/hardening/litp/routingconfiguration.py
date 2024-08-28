from node_hardening.hardening.base import BaseHardening, CommandExecutionException, StopHardeningExecution


class RoutingConfiguration(BaseHardening):
    section = 'RoutingConfiguration'


class SourceRoutingDisabled(RoutingConfiguration):
    topic = 'source_routing_disabled'
    sysctl_params = [
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.all.forwarding",
        "net.ipv6.conf.all.forwarding",
        "net.ipv4.conf.all.mc_forwarding",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv6.conf.all.accept_redirects",
        "net.ipv4.conf.all.secure_redirects",
        "net.ipv4.conf.all.send_redirects"
    ]

    def check(self):
        out = self.ssh.run("/sbin/sysctl -a")
        values = []
        for line in out.splitlines():
            for param in self.sysctl_params:
                if param.split('.')[-1] in line:
                    values.append(bool(param.split(' = ')[-1]))
        return self.all_exclusive(values)

    def harden(self):
        """ Ensure that source routing is enabled via sysctl commands.
        """
        report = {}
        sysctl_cmd = "/sbin/sysctl -w %s=%s"
        value = int(not self.expected_value)
        status_name = lambda x: "disabled" if not x else "enabled"

        for param in self.sysctl_params:
            try:
                self.ssh.run(sysctl_cmd % (param, value))
                report[param] = status_name(value)
            except CommandExecutionException:
                cmd = "/sbin/sysctl -a | grep %s" % param.split('.')[-1]
                output = self.ssh.run(cmd)
                failed = []
                for line in output.splitlines():
                    p, v = line.split(' = ')
                    report[param] = status_name(not v)
                    if v != str(value):
                        failed.append(p)
                if failed:
                    raise StopHardeningExecution("The following Sysctl "
                                                "parameters should be %s: %s" %
                                       (status_name(value), ', '.join(failed)))
        return report
