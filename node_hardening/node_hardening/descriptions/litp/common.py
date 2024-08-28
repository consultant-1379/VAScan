
from node_hardening.basedescription import HardeningDescription
from node_hardening.utils import get_list_from_file

from node_hardening.basesections import BaseOsInstallation, BaseOsConfiguration, \
    BaseFileSystem, BaseLoginControl, BaseSystemAccessControl, \
    BaseSecurityPatchManagement, BasePkiTrustRelationshipConfiguration, \
    BaseNetworkConfiguration, BaseRoutingConfiguration, \
    BaseFirewallConfiguration, BaseSecuringServices, \
    BaseLoggingConfiguration, BaseTimeSynchronisation, \
    BasePasswordEncryption, BaseVirtualMachineHardening


class CommonDescription(HardeningDescription):
    name = 'common'
    ntp_server = ''
    grub_password = 'passw0rd'


@CommonDescription.section
class OsInstallation(BaseOsInstallation):
    packages = []
    selinux_enabled = True
    selinux_enforced = True


@CommonDescription.section
class OsConfiguration(BaseOsConfiguration):
    processes = []
    running_services = []
    known_services = []
    services_ports = {}
    x_windows_used = False
    system_cron_jobs = []
    cron_jobs_per_user = {}
    # suid_files = get_list_from_file('litp/suid_files.txt')
    # sgid_files = get_list_from_file('litp/sgid_files.txt')
    sgid_files = []
    suid_files = []


@CommonDescription.section
class FileSystem(BaseFileSystem):
    auto_mount_enabled = False


@CommonDescription.section
class LoginControl(BaseLoginControl):
    password_age = 60  # days
    idle_timeout = 300  # sec


@CommonDescription.section
class SystemAccessControl(BaseSystemAccessControl):
    account_locking = (5,      # deny login after 5 failed login attempts
                       21600)  # login access is allowed again after 21600s(6h)
    login_banner_present = True


@CommonDescription.section
class PkiTrustRelationshipConfiguration(BasePkiTrustRelationshipConfiguration):
    pass


@CommonDescription.section
class NetworkConfiguration(BaseNetworkConfiguration):
    pass


@CommonDescription.section
class RoutingConfiguration(BaseRoutingConfiguration):
    source_routing_disabled = True


@CommonDescription.section
class FirewallConfiguration(BaseFirewallConfiguration):
    pass


@CommonDescription.section
class SecuringServices(BaseSecuringServices):
    telnet_server_installed = False
    telnet_client_installed = False
    ftp_installed = False
    ports_not_in_use = [21, 23]
    max_logins = 10  # ten shells per user


@CommonDescription.section
class LoggingConfiguration(BaseLoggingConfiguration):
    pass


@CommonDescription.section
class TimeSynchronisation(BaseTimeSynchronisation):
    pass


@CommonDescription.section
class PasswordEncryption(BasePasswordEncryption):
    grub_password_encrypted = True


@CommonDescription.section
class VirtualMachineHardening(BaseVirtualMachineHardening):
    pass
