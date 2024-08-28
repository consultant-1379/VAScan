from .common import CommonDescription, TimeSynchronisation, \
                    OsConfiguration, OsInstallation
from node_hardening.utils import get_list_from_file


class NodeDescription(CommonDescription):
    name = 'node'
    ntp_server = '10.44.86.212'


@NodeDescription.section
class OsInstallation(OsInstallation):
    #packages = get_list_from_file('litp/node_packages.txt')
    packages = []


@NodeDescription.section
class OsConfiguration(OsConfiguration):
    processes = []
    running_services = []
    known_services = []
    services_ports = {}
    system_cron_jobs = []
    cron_jobs_per_user = {}


@NodeDescription.section
class TimeSynchronisation(TimeSynchronisation):
    ntp_sync_enabled = True
