
import os
from datetime import datetime
from decimal import Decimal
from node_hardening.basedescription import FailedOrIncompleteTopicsException

BASE_DIR = os.path.dirname(os.path.dirname(__file__))


class Table(object):

    def __init__(self, title, data, dict_lines=False):
        self.title = title
        self.data = data
        self.dict_lines = dict_lines

    def format_dict(self, format):
        trs = []
        f = format.DictToTable
        if self.dict_lines:
            ths = [f.td % i for i in self.data[0].keys()]
            trs.append(f.tr % ''.join(ths))
            for line in self.data:
                tds = [f.td % ''.join(format.format_dict_list(i))
                       for i in line.values()]
                trs.append(f.tr % ''.join(tds))
        else:
            for key, value in self.data.items():
                tds = [f.td % key]
                if isinstance(value, list):
                    for item in value:
                        tds.append(f.td % item)
                else:
                    tds.append(f.td % value)
                trs.append(f.tr % ''.join(tds))
        lines = ['<br><strong>%s</strong><br>' % self.title]
        lines += (f.table % ''.join(trs)).splitlines()
        return lines


class ReportFormatter(object):
    hr = None
    h1 = None
    h2 = None
    h3 = None
    ul = None
    ul_end = None
    li = None
    br = None
    pre = None
    div = None
    span = None
    strong = None
    error = None

    class DictList:
        key = None
        value = None
        simple_value = None
        list_topic = None
        list_block = None

    class DictToTable:
        table = None
        tr = None
        td = None

    @classmethod
    def format_dict_list(cls, dictionary, ignore_keys=None):
        lines = []
        f = cls.DictList
        def _format(d, ignore_keys):
            if ignore_keys is None:
                ignore_keys = []
            if isinstance(d, dict):
                lines.append(f.list_block[0])
                for k, v in d.iteritems():
                    if k in ignore_keys:
                        continue
                    name = f.key % k
                    if isinstance(v, dict) or isinstance(v, list):
                        lines.append(f.value % name)
                        _format(v, ignore_keys)
                    else:
                        value = f.simple_value % unicode(v)
                        lines.append(f.value % (name + value))
                lines.append(f.list_block[1])
            elif isinstance(d, list):
                lines.append(f.list_block[0])
                for i in d:
                    if isinstance(i, dict) or isinstance(i, list):
                        if isinstance(i, dict):
                            for ig in ignore_keys:
                                if i.has_key(ig):
                                    del i[ig]
                            if len(i.keys()) > 1:
                                _format(i, ignore_keys)
                            elif len(i.keys()) == 1:
                                value = f.simple_value % i.values()[0]
                                lines.append(f.list_topic % value)
                        else:
                            _format(i, ignore_keys)
                    else:
                        value = f.simple_value % unicode(i)
                        lines.append(f.list_topic % value)
                lines.append(f.list_block[1])
            else:
                lines.append(str(d))
        _format(dictionary, ignore_keys)
        return lines


class TextReportFormat(ReportFormatter):
    hr = '#' * 80
    h1 = '### %s'
    h2 = '## %s'
    h3 = '# %s'
    h4 = '* %s'
    ul = ''
    ul_end = ''
    ul_vis = ''
    ul_vis_end = ''
    li_begin = ''
    li_end = ''
    li = ' - %s'
    a = '%s %s'
    a_anchor = '%(title)s'
    br = ''
    pre = '%s'
    div = '%s'
    scroll = ''
    scroll_end = ''
    span = '%s'
    strong = '*%s*'
    traceback = '%s'
    error = '!!! %s !!!'
    harden_not_implemented = ':( %s'
    warning = '! %s !'
    fail_icon = '!!'
    error_icon = '!!!'
    secret_icon = '\/ %s'
    warning_icon = '!'
    harden_not_implemented_icon = ':('
    flag_icon = 'P(%s)'
    checked_icon = 'V'
    space = ' '

    class DictList:
        key = "#%s: "
        value = '%s'
        simple_value = "%s"
        list_topic = '%s'
        list_block = ('', '')

    class DictToTable:
        table = '%s'
        tr = '%s\n'
        td = '%s          '


class HtmlReportFormat(ReportFormatter):
    hr = '<hr>'
    h1 = '<h1>%s</h1>'
    h2 = '<h2>%s</h2>'
    h3 = '<h3>%s</h3>'
    h4 = '<h4>%s</h4>'
    ul = '<ul>'
    ul_end = '</ul>'
    ul_vis = '<ul class="visible fullheight">'
    ul_vis_end = '</ul>'
    li_begin = '<li>'
    li_end = '</li>'
    li = '<li>%s</li>'
    a = '<a href="#%s">%s</a>'
    a_anchor = '<a class="anchor" href="#%(id)s" name="%(id)s">%(title)s</a>'
    br = '<br>'
    pre = '<pre>%s</pre>'
    div = '<div>%s</div>'
    scroll = '<div class="scroll">'
    scroll_end = '</div>'
    span = '<span>%s</span>'
    strong = '<strong>%s</strong>'
    traceback = '<pre class="traceback">%s</pre>'
    error = '<div class="error"><i class="fa fa-exclamation-circle fa-1x"></i> %s</div>'
    harden_not_implemented = '<div class="warning"><i class="fa fa-thumbs-o-down fa-1x"></i> %s</div>'
    warning = '<div class="warning"><i class="fa fa-exclamation-triangle fa-1x"></i> %s</div>'
    fail_icon = ' <i class="fa fa-exclamation fa-1x red"></i>'
    error_icon = ' <i class="fa fa-exclamation-circle fa-1x red"></i>'
    warning_icon = ' <i class="fa fa-exclamation-triangle fa-1x orange"></i>'
    harden_not_implemented_icon = ' <i class="fa fa-thumbs-o-down fa-1x red"></i>'
    secret_icon = ' <i title="%s" class="fa fa-user-secret fa-1x red"></i>'
    flag_icon = ' <i title="%s" class="fa fa-flag fa-1x dark-blue"></i>'
    checked_icon = ' <i title="%s" class="fa fa-check fa-1x dark-green"></i>'
    space = '&nbsp;'

    class DictList:
        key = "<strong>%s: </strong>"
        value = '<li>%s</li>'
        simple_value = "%s"
        list_topic = '<li class="list_value">%s</li>'
        list_block = ('<ul class="visible">', '</ul>')

    class DictToTable:
        table = '<table>%s</table>'
        tr = '<tr>%s</tr>\n'
        td = '<td>%s</td>'


class ReportBuilder(object):

    def __init__(self, description):
        self.description = description

    def to_text(self):
        return self.build_formated_lines(TextReportFormat)

    def to_html(self):
        path = os.path.join(BASE_DIR, "node_hardening", "report_format.html")
        with open(path) as f:
            html_base = f.read()
        body = self.build_formated_lines(HtmlReportFormat)
        title = "Hardening Report for %s" % str(self.description.host)
        return html_base % dict(body=body, title=title)

    def build_formated_lines(self, format):
        lines = []
        format_topic_name = lambda x: x.title().replace('_', ' ')
        kv = lambda k, v: format.div % ("%s %s" % (format.strong % ("%s:" % k),
                                                   format.span % v))
        now = datetime.now().isoformat(" ").split('.')[0][:-3]
        lines.append(format.br)
        lines.append(kv("Baseline description used", self.description.name))
        lines.append(kv("Host", self.description.host))
        lines.append(kv("Executed at", now))
        if self.description.duration:
            dur = str(self.description.duration)
            duration = Decimal(dur).quantize(Decimal('.0'))
            lines.append(kv("Duration", "%ss" % duration))

        try:
            self.description.check_failed_topics()
        except FailedOrIncompleteTopicsException as err:
            lines.append(format.br)
            if err.failed_topics:
                lines.append(format.error % "Hardening Failed")
                lines.append(format.br)
            if err.incomplete_topics:
                lines.append(format.warning % "Hardening Incomplete")
                lines.append(format.br)

        lines.append(format.h1 % (format.a_anchor % dict(id="__index",
                                                         title="INDEX")))

        lines.append(format.ul_vis)
        for section in self.description.sections:
            if not [t for i, t in section.topics if t.is_defined()]:
                # ignore not defined topics...
                continue
            lines.append(format.li_begin)
            lines.append(format.strong % (format.a % (section, section)))
            lines.append(format.ul_vis)
            for name, topic in section.topics:
                if topic.just_report:
                    title = format_topic_name(name)
                else:
                    title = "%s: %s" % (format_topic_name(name),
                                         topic.expected_value)
                a = (format.a % (name, title))
                alert_icon = ""
                if topic.error:
                    alert_icon = format.fail_icon
                elif topic.unhandled_error:
                    alert_icon = format.error_icon
                elif topic.harden_case_not_implemented:
                    alert_icon = format.harden_not_implemented_icon
                elif topic.is_incomplete():
                    alert_icon = format.warning_icon
                else:
                    alert_icon = format.checked_icon
                alert_icon += format.space
                extra = ""
                if topic.just_report:
                    extra = format.flag_icon % "This topic is just a report"
                if topic.checked_and_hardened:
                    extra += format.secret_icon % "It was checked and hardened"
                lines.append(format.li % ("%s %s %s" % (alert_icon, a, extra)))
            lines.append(format.ul_vis_end)
            lines.append(format.br)
            lines.append(format.li_end)
        lines.append(format.ul_vis_end)
        lines.append(format.br)
        lines.append(format.hr)

        if self.description.ignored_topics:
            lines.append(format.h2 % (format.a_anchor % dict(id="__ignored",
                                                title="IGNORED TOPICS")))
            lines.append(format.ul_vis)
            for section, topic in self.description.ignored_topics:
                lines.append(format.li_begin)
                title = "%s: %s" % (section, format_topic_name(topic))
                lines.append(format.span % title)
                lines.append(format.li_end)
            lines.append(format.ul_vis_end)
            lines.append(format.br)
            lines.append(format.br)
            lines.append(format.hr)


        for section in self.description.sections:
            if not [t for i, t in section.topics if t.is_defined()]:
                # ignore not defined topics...
                continue
            section_desc = section.doc_string
            lines.append(format.h1 % ("%s %s" % (
                format.a_anchor % dict(id=section, title=section),
                format.a_anchor % dict(id="__index", title='^')
            )))
            lines.append(format.div % section_desc)
            lines.append(format.br)
            for name, topic in section.topics:
                lines.append(format.h2 % ("%s %s" % (
                    format.a_anchor % dict(id=name,
                                           title=format_topic_name(name)),
                    format.a_anchor % dict(id='__index',
                                           title='^')
                    )))
                lines.append(format.div % topic.description)
                lines.append(format.br)
                if not topic.just_report:
                    lines.append(format.strong % "Expected: ")
                    if isinstance(topic.expected_value, list):
                        if len(topic.expected_value) < 4:
                            lines.append(format.span % str(topic.expected_value))
                        else:
                            lines.append(format.scroll)
                            for item in topic.expected_value:
                                lines.append(format.span % item)
                                lines.append(format.br)
                            lines.append(format.scroll_end)
                    else:
                        lines.append(format.span % str(topic.expected_value))
                    if topic.expected_value != topic.retrieved_value:
                        lines.append(format.span %
                         (" but got %s instead." % str(topic.retrieved_value)))
                if topic.report:
                    lines.append(format.h3 % 'Summary results')
                    if topic.just_report:
                        reports = [format.flag_icon,
                                format.strong % "This topic is just a report."]
                    elif topic.checked_and_hardened:
                        reports = [format.secret_icon % "It was checked and hardened",
                                   "It was checked and hardened."]
                    else:
                        reports = [format.checked_icon]
                    rep = topic.report if isinstance(topic.report, list) else [topic.report]
                    reports += rep
                    for report in reports:
                        if isinstance(report, Table):
                            lines.append(format.scroll)
                            lines += report.format_dict(format)
                            lines.append(format.scroll_end)
                        else:
                            lines += format.format_dict_list(report)
                if topic.outputs:
                    lines.append(format.br)
                    lines.append(format.br)
                    if topic.harden_outputs:
                        lines.append(format.div % 'Commands executed during '
                                                  'the first check process:')
                    else:
                        if topic.just_report:
                            lines.append(format.div % 'Commands executed '
                                                  'during the report process:')
                        else:
                            lines.append(format.div % 'Commands executed '
                                                   'during the check process:')
                    lines.append(format.br)
                    for cmd, code, output in topic.check_outputs:
                        lines.append(format.div % ('$ %s' % cmd))
                        lines.append(format.pre % "STATUS CODE: %s\n%s\n\n%s" %
                                     (code, '-' * 80, output))
                    if topic.harden_outputs:
                        lines.append(format.br)
                        lines.append(format.div % 'Commands executed during '
                                                  'the hardening process:')
                        lines.append(format.br)
                        for cmd, code, output in topic.harden_outputs:
                            lines.append(format.div % ('$ %s' % cmd))
                            lines.append(format.pre % "STATUS CODE: %s\n%s\n\n%s" %
                                         (code, '-' * 80, output))
                    if topic.double_check_outputs:
                        lines.append(format.br)
                        lines.append(format.div % 'Commands executed during '
                                                  'the second check process:')
                        lines.append(format.br)
                        for cmd, code, output in topic.double_check_outputs:
                            lines.append(format.div % ('$ %s' % cmd))
                            lines.append(format.pre % "STATUS CODE: %s\n%s\n\n%s" %
                                         (code, '-' * 80, output))

                lines.append(format.br)
                lines.append(format.br)
                if topic.error:
                    error = topic.error
                    if 'Traceback (most recent call last)' in error:
                        error = "Python Unhandled Exception\n%s" % \
                                (format.traceback % error)
                    lines.append(format.error % "Hardening Failed: %s" % error)
                    lines.append(format.br)
                if topic.unhandled_error:
                    error = topic.unhandled_error
                    if 'Traceback (most recent call last)' in error:
                        error = "Python Unhandled Exception\n%s" % \
                                (format.traceback % error)
                    lines.append(format.error % "Unexpected error: %s" % error)
                    lines.append(format.br)

                if topic.harden_case_not_implemented:
                    m = topic.harden_case_not_implemented
                    msg = m if isinstance(m, str) else\
                          "Harden case not implemented"
                    lines.append(format.harden_not_implemented % msg)
                    lines.append(format.br)
                elif topic.is_incomplete():
                    lines.append(format.warning % "Hardening incomplete for "
                                                  "this topic...")
                    lines.append(format.br)
                lines.append(format.hr)
            lines.append(format.br)
            lines.append(format.br)
        return '\n'.join(lines)
