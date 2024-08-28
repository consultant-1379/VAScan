
import re

from collections import OrderedDict


class BaseParser(object):

    def __init__(self, output):
        self.output = output

    @property
    def lines(self):
        return self.output.splitlines()

    def parse(self):
        raise NotImplementedError


class NTPOutputParser(BaseParser):
    """
    The currently selected peer is marked *,
    while additional peers designated acceptable
    for synchronization, but not
    currently selected, are marked +.
    """

    def parse(self):
        ip = None
        for line in self.output.splitlines():
            if line.startswith('*'):
                ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
                break
        if ip:
            return ip[0]


class PropertiesOutputParser(BaseParser):

    def parse(self):
        data = {}
        key = None
        for line in self.output.splitlines():
            if ':' in line:
                key, value = map(lambda x: x.strip(), line.split(':'))
                data[key] = value
            else:
                if key:
                    if not isinstance(data[key], list):
                        data[key] = []
                    data[key].append(value)
        return data


class LitpPlanOutputParser(BaseParser):
    status_regex = re.compile(r'Tasks:\s+(?P<tasks>\d+)\s+\|\s+'
                              r'Initial:\s+(?P<initial>\d+)\s+\|\s+'
                              r'Running:\s+(?P<running>\d+)\s+\|\s+'
                              r'Success:\s+(?P<success>\d+)\s+\|\s+'
                              r'Failed:\s+(?P<failed>\d+)\s+\|\s+'
                              r'Stopped:\s+(?P<stopped>\d+).*')

    def parse(self):
        blocks = self.output.strip().split('\n\n')
        phases_str = [b for b in blocks if b.strip().startswith('Phase ')]
        summary_str = [b for b in blocks if
                       b.strip().startswith('Tasks: ')][0].strip()
        phases = []
        for phase_str in phases_str:
            phases.append(self._parse_phase(phase_str))
        summary = self._parse_summary(summary_str)
        summary['phases'] = phases
        return summary

    def _parse_phase(self, phase_str):
        phase = dict()
        lines = phase_str.splitlines()
        phase['number'] = lines[0].split()[-1]
        phase['status'] = lines[3].split()[0].strip()
        phase['vpath'] = lines[3].split()[-1].strip()
        phase['description'] = ' '.join([i.strip() for i in lines[4:]])
        return phase

    def _parse_summary(self, summary_str):
        summary = dict()
        lines = [i for i in summary_str.splitlines() if i.strip()]
        match = self.status_regex.match(lines[0])
        summary['count'] = match.groupdict()
        summary['status'] = lines[-1].split('Plan Status:')[-1].strip()
        return summary


class LitpModelItemOutputParser(BaseParser):

    def parse(self):
        result_data = {}
        lines = [i for i in self.lines if i.strip()]
        result_data['vpath'] = lines.pop(0)
        data = result_data
        properties = False
        parent = data
        for line in lines:
            if isinstance(data, list):
                value = line.strip()
                key = None
            else:
                key, value = map(lambda x: x.strip(), line.split(':', 1))
            if not value:
                key = key.replace(' (inherited properties are marked with '
                                  'asterisk)', '')
                if key == 'children':
                    parent[key] = []
                    properties = False
                else:
                    parent[key] = {}
                data = parent[key]
                if key == 'properties':
                    properties = True
                continue
            if properties:
                value = dict(value=value, inherited=False)
                if '[*]' in value['value']:
                    value['value'] = value['value'].split('[*]')[0].strip()
                    value['inherited'] = True
            if key:
                data[key] = value
            else:
                data.append(value)
        return result_data


class RealUsersParser(BaseParser):

    def parse(self):
        users = []
        for line in self.output.splitlines():
            items = line.split(':')
            if len(items) != 7:
                continue
            username = items[0]
            user_id = items[2]
            if int(user_id) > 499 and username != "nfsnobody":
                users.append(username)
        return users


class KeyValuesListOutputParser(BaseParser):

    def parse(self):
        data = {}
        for line in self.lines:
            if not line.strip():
                continue
            values = line.split()
            key = values.pop(0)
            data.setdefault(key, [])
            data[key] += values
        return data


class TwoColumnsKeyValueOutputParser(BaseParser):

    def parse(self):
        data = {}
        for line in self.lines:
            if not line.strip():
                continue
            values = line.split()
            key = values.pop(0)
            data.setdefault(key, [])
            data[key].append(' '.join(values))
        return data


class TwoColumnsKeyValueSumOutputParser(TwoColumnsKeyValueOutputParser):

    def parse(self):
        data = super(TwoColumnsKeyValueSumOutputParser, self).parse()
        return OrderedDict(sorted([(k, sum([float(i) for i in v])) for k, v
                      in data.items()], lambda a, b: -1 if a[1] > b[1] else 1))


class ServicesStatusesParser(BaseParser):

    running_regex = re.compile(r'([\w\-\.]+)\s+.*is running\.\.\.$')
    stopped_regex = re.compile(r'([\w\-\.]+)\s+.*is stopped$')

    def parse(self):
        data = {}
        for line in self.lines:
            running_match = self.running_regex.match(line)
            if running_match:
                key = running_match.groups()[0]
                data[key] = True
            stopped_match = self.stopped_regex.match(line)
            if stopped_match:
                key = stopped_match.groups()[0]
                data[key] = False
        return data


class NetstatTulpnOutputParser(BaseParser):

    def parse(self):
        data = {}
        start = False
        for line in self.lines:
            cels = line.split(None, 6)
            if not start and cels[0] == 'Proto':
                start = True
                continue
            if not start:
                # skip first lines and header
                continue
            state_empty = len(cels) == 6
            pid_name = cels.pop()
            try:
                pid, name = pid_name.split('/')
            except ValueError:
                if not pid_name.strip() == '-':
                    raise
                pid, name = '', ''
            if not state_empty:
                state = cels.pop()
            foreign = self.parse_ip_port(cels.pop())
            local = self.parse_ip_port(cels.pop())
            send_q = cels.pop()
            recv_q = cels.pop()
            proto = cels.pop()
            data.setdefault(name, [])
            data[name].append(dict(pid=pid, state=state, local=local,
                foreign=foreign, send_q=send_q, recv_q=recv_q, proto=proto))
        return data

    def parse_ip_port(self, address):
        splited = address.split(':')
        port = splited.pop()
        ip = ':'.join(splited)
        return dict(ip=ip, port=port)


class CrontabJobsPerUserParser(BaseParser):

    no_crontab_regex = re.compile(r'^no\scrontab\sfor\s([\w\-\.]+)')
    user_regex = re.compile(r'^__([\w\-\.]+)$')

    def parse(self):
        data = {}
        user = None
        for line in self.lines:
            if not line.strip():
                continue
            match = self.user_regex.match(line)
            if match:
                user = match.groups()[0]
                continue
            match = self.no_crontab_regex.match(line)
            if match:
                continue
            if user is None:
                continue
            data.setdefault(user, [])
            data[user].append(line)
        return data
