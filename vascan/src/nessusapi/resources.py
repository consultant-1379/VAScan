
import time
import socket
from urllib2 import URLError

from nessusapi.base import Resource, NessusApiError
from nessusapi.objects import Scan
from nessusapi.templatetypes import TemplateTypes


class EditorResource(Resource):
    base_uri = '/editor'
    list_uri = '/editor/%s/templates'
    get_uri = '/editor/%s/templates/%s'


class ScanStatus(object):
    running = 'running'
    stopping = 'stopping'
    pausing = 'pausing'
    resuming = 'resuming'
    canceled = 'canceled'
    completed = 'completed'
    paused = 'paused'

    finished = [stopping, canceled, completed]


class ExportFormat(object):
    nessus = 'nessus'
    csv = 'csv'
    db = 'db'
    html = 'html'
    pdf = 'pdf'


class PolicyResource(Resource):
    base_uri = '/policies'
    list_uri = base_uri
    get_uri = "%s/%%s" % base_uri
    create_uri = base_uri
    delete_uri = get_uri

    def get_policy_id(self, name):
        data = self.api.request.get(self.base_uri)
        for policy in data['policies']:
            if policy['name'] == name:
                return policy['id']
        raise NessusApiError('Policy: {0} not found on Nessus'.format(name))

    def get_policy_names(self):
        data = self.api.request.get(self.base_uri)
        return [policy['name'] for policy in data['policies']]


class ScansResource(Resource):
    base_uri = '/scans'
    list_uri = base_uri
    get_uri = "%s/%%s" % base_uri
    create_uri = base_uri
    delete_uri = get_uri

    def create(self, name, policy_id, targets, enabled=False,
               template=TemplateTypes.AdvancedScan, description=None,
               launch=None, starttime=None, folder_id=None, scanner_id=None,
               rrules=None, timezone=None, emails=None, acls=None,
               use_dashboard=None):
        kwargs = locals()
        settings = dict([(k, v) for k, v in kwargs.items() if v is not None])
        settings.pop('self')
        settings.pop('template')
        settings['text_targets'] = settings.pop('targets')
        uuid = template.get_uuid(self.api)
        self._validate_base_uri()
        data = self.api.request.post(self.create_uri, uuid=uuid,
                                     settings=settings)
        # return Scan(self, data, data['scan'])
        return data

    def _do(self, action, scan_id, **kwargs):
        url = "%s/%s" % (self.get_uri % scan_id, action)
        return self.api.request.post(url, **kwargs)

    def pause(self, scan_id):
        return self._do('pause', scan_id)

    def resume(self, scan_id):
        return self._do('resume', scan_id)

    def stop(self, scan_id):
        return self._do('stop', scan_id)

    def launch(self, scan_id):
        return self._do('launch', scan_id)

    def launch_and_wait(self, scan_id):
        data = self._do('launch', scan_id)
        if 'scan_uuid' not in data:
            raise Exception(str(data))
        while not self.is_scan_finished(scan_id):
            time.sleep(10)

    def is_scan_finished(self, scan_id):
        url = self.get_uri % scan_id
        try:
            status = self.api.request.get(url)['info']['status']
        except (URLError, socket.error) as err:
            print(err)
            return False
        return status in ScanStatus.finished

    def export(self, scan_id, export_format='pdf',
               include_chapters='vuln_hosts_summary;vuln_by_host;'
                                'compliance_exec;remediations;'
                                'vuln_by_plugin;compliance'):
        """ Exports a scan to the "export_format" and returns the file_id.
            We have to specify the chapters that will be included in the
            exported security report. By default all chapters are specified for
            the security report.
            If non of the chapters are specified the security report will not
            have any chapters included and the security report will have only
            heading in it.
        :param scan_id: The ID of the scanning process
        :param export_format: One of the available report format
        :param include_chapters: Chapters that will be included in report
        :return: file id
        """
        data = self._do('export', scan_id, format=export_format,
                        chapters=include_chapters)
        file_id = data['file']
        return file_id

    def get_export_status(self, scan_id, file_id):
        url = "%s/export/%s/status" % (self.get_uri % scan_id, file_id)
        data = self.api.request.get(url)
        return data['status']

    def download_export(self, scan_id, file_id):
        url = "%s/export/%s/download" % (self.get_uri % scan_id, file_id)
        return self.api.request.get(url)

    def export_and_download(self, scan_id, export_format='pdf'):
        """ There are 3 steps to do:
         - Export;
         - Poling to check if the export is ready;
         - Download.
        :param scan_id:
        :param export_format:
        :return: downloaded file
        """
        file_id = self.export(scan_id, export_format)

        is_ready = lambda: self.get_export_status(scan_id, file_id) == 'ready'

        while not is_ready():
            time.sleep(2)
        return self.download_export(scan_id, file_id)
