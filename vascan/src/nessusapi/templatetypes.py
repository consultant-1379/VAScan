

class T(object):

    def __init__(self, title, uuid=None):
        self.title = title
        self._uuid = uuid

    def __str__(self):
        return self.title

    def get_uuid(self, api):
        if self._uuid is None:
            templates = api.editor.list('scan')['templates']
            self._uuid = [t['uuid'] for t in templates
                          if t['title'] == self.title][0]
        return self._uuid


class TemplateTypes(object):
    PCIQuarterlyExternalScan = T('PCI Quarterly External Scan')
    HostDiscovery = T('Host Discovery')
    BasicNetworkScan = T('Basic Network Scan')
    CredentialedPatchAudit = T('Credentialed Patch Audit')
    WebApplicationTests = T('Web Application Tests')
    WindowsMalwareScan = T('Windows Malware Scan')
    MobileDeviceScan = T('Mobile Device Scan')
    MDMConfigAudit = T('MDM Config Audit')
    PolicyComplianceAuditing = T('Policy Compliance Auditing')
    InternalPCINetworkScan = T('Internal PCI Network Scan')
    OfflineConfigAudit = T('Offline Config Audit')
    AuditCloudInfrastructure = T('Audit Cloud Infrastructure')
    SCAPandOVALAuditing = T('SCAP and OVAL Auditing')
    CustomScan = T('Custom Scan')
    BashShellshockDetection = T('Bash Shellshock Detection')
    GHOST_glibc_Detection = T('GHOST (glibc) Detection')
    AdvancedScan = T('Advanced Scan')