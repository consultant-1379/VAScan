from .common import CommonDescription, VirtualMachineHardening, \
    OsConfiguration, OsInstallation


class KvmDescription(CommonDescription):
    name = 'KVM'


@KvmDescription.section
class OsInstallation(OsInstallation):
    packages = []


@KvmDescription.section
class OsConfiguration(OsConfiguration):
    processes = []
    running_services = []
    known_services = []
    services_ports = {}
    system_cron_jobs = []
    cron_jobs_per_user = {}


@KvmDescription.section
class VirtualMachineHardening(VirtualMachineHardening):
    root_ssh_access = False
