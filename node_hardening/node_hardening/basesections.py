from node_hardening.section import Section, Topic


class BaseOsInstallation(Section):
    """ Node hardening steps for the Operating System installation.
    """
    packages = Topic(list, "Only the necessary OS components are installed "
                           "(@core --nobase + list of specified RPMs).")
    unwanted_packages = Topic(list, "List of unwanted packages on the LITP "
                                    "cluster level.")
    selinux_enabled = Topic(bool, "Ensure that SELinux is <enabled|disabled>.")
    selinux_enforced = Topic(bool, "Ensure that SELinux is <|not> in "
                                   "enforcing mode.")


class BaseOsConfiguration(Section):
    """ Node hardening steps for the Operating System configuration.
    """
    processes = Topic(list, "Ensure that only relevant processes are running.")
    #mem_per_processes = Topic(dict)
    running_services = Topic(list, "Ensure that only relevant services are "
                                   "running.")
    known_services = Topic(list, "Report of known services.")
    services_ports = Topic(dict, "Report of services and associated ports.")
    x_windows_used = Topic(bool, "Ensure or not X-Windows is <|not> in use")
    system_cron_jobs = Topic(list, "Report a list of cron jobs in the system.")
    cron_jobs_per_user = Topic(dict, "Report a list of cron jobs per user.")
    suid_files = Topic(list, "Ensure that no additional SUID files have "
                             "been added.")
    sgid_files = Topic(list, "Ensure that no additional SGID files have "
                             "been added.")


class BaseSecurityPatchManagement(Section):
    """ Node hardening steps for the Security Patch Management
    """


class BaseFileSystem(Section):
    """ Node hardening steps for File Systems
    """
    auto_mount_enabled = Topic(bool, "Ensure that NFS auto mount is <|not>"
                                     "used.")
    #writable_files_directories = Topic(dict)


class BaseSystemAccessControl(Section):
    """ Node hardening steps for System access control, authentication and
    authorisation.
    """
    account_locking = Topic(tuple, "Ensure that accounts are locked after a "
                                   "certain number of failed login attempts.")

    login_banner_present = Topic(bool, "Ensures a login banner is present.")


class BaseLoginControl(Section):
    """ Node hardening steps for Password and login control.
    """
    password_age = Topic(int, "Ensure the password age for users.")
    idle_timeout = Topic(int, "Ensure inactive login session times out"
                              " after a given number of sec.")


class BasePkiTrustRelationshipConfiguration(Section):
    """ Node hardening steps for PKI and trust relationship configuration.
    """


class BaseNetworkConfiguration(Section):
    """ Node hardening steps for Network configuration.
    """


class BaseRoutingConfiguration(Section):
    """ Node hardening steps for Routing configuration.
    """
    source_routing_disabled = Topic(bool, "Ensure that source routing is "
                                         "<disabled|enabled>")


class BaseFirewallConfiguration(Section):
    """ Node hardening steps for Host-based firewall configuration.
    """
    plugin_installed = Topic(bool, "Ensure that the firewall plugin is "
                                   "<|not> installed.")
    plugin_enabled = Topic(bool, "Ensure that the firewall is "
                                 "<enabled|disabled>.")
    tftp_port_disabled = Topic(bool, "Ensure ftfp port <closed|open> on MS "
                                     "and nodes")


class BaseSecuringServices(Section):
    """ Node hardening steps for Securing services.
    """
    telnet_client_installed = Topic(bool, "Ensure that telnet client is "
                                          "<|not> installed.")
    telnet_server_installed = Topic(bool, "Ensure that telnet server is "
                                          "<|not> installed.")
    ftp_installed = Topic(bool, "Ensure that ftp is <|not> installed.")
    ports_not_in_use = Topic(list, "Ensure ports not opened.")
    max_logins = Topic(int, "Ensure the max number of login shells per users.")


class BaseLoggingConfiguration(Section):
    """ Node hardening steps for Logging configuration.
    """


class BaseAuditing(Section):
    """ Node hardening steps for Auditing.
    """
    #auditing_enabled = Topic(bool, "Ensure that system auditing is "
    #                               "<enabled|disabled>")


class BaseTimeSynchronisation(Section):
    """ Node hardening steps for Time synchronisation.
    """
    ntp_sync_enabled = Topic(bool, "Ensure that ntp sync is "
                                   "<enabled|disabled>.")


class BasePasswordEncryption(Section):
    """ Node hardening steps for Password Encryption.
    """
    grub_password_encrypted = Topic(bool, "Ensure that password is <|not>"
                                     "encrypted.")


class BaseVirtualMachineHardening(Section):
    """ Node hardening steps for Virtual Machine Hardening on the Peer Servers.
    """
    root_ssh_access = Topic(bool, "Ensure that root SSH access is <|not> "
                                  "removed.")

