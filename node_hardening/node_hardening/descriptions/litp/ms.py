
from .common import CommonDescription, OsConfiguration, \
    FirewallConfiguration, OsInstallation
from node_hardening.utils import get_list_from_file


class MsDescription(CommonDescription):
    name = 'MS'


@MsDescription.section
class OsInstallation(OsInstallation):
    # packages = get_list_from_file('litp/ms_packages.txt')
    packages = []
    #unwanted_packages = ['httpd', 'cups']  # !! this applies only for nodes !!


@MsDescription.section
class OsConfiguration(OsConfiguration):
    processes = []
    running_services = []
    known_services = []
    services_ports = {}
    system_cron_jobs = []
    cron_jobs_per_user = {}


@MsDescription.section
class FirewallConfiguration(FirewallConfiguration):
    plugin_installed = True
    tftp_port_disabled = True
