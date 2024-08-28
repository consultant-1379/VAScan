import inspect

from node_hardening import basesections
from node_hardening.section import Section
from node_hardening.utils import camelcase_to_underscore


class IncompleteHardeningDefinition(Exception):
    """ This exception is raised in the constructor of HardeningDescription in
    case the definitions of sections are incomplete for the description in
    context.
    """


class FailedOrIncompleteTopicsException(Exception):
    """ In case any of failed or incomplete topics, this exception must be
    raised.
    """

    def __init__(self, failed, incomplete, no_hardener_implemented):
        self.failed_topics = failed
        self.incomplete_topics = incomplete
        self.no_hardener_implemented_topics = no_hardener_implemented


class HardeningDescription(object):
    """ Base class for a Hardening description.
    """
    name = None

    def __init__(self, host):
        """ It requires the host argument to just include in the report. THis
        constructor also checks if all section where properly defined and
        registered using the decorator @HardeningDescription.section.
        """
        self.host = host
        missing = []
        sections = []
        self.duration = None
        self.ignored_topics = []
        for section_attr, name in self.sections_names():
            section = getattr(self, section_attr)
            if not section:
                missing.append('The section class "%s" must be defined and '
                               'registered.' % name)
            sections.append(section)
        if missing:
            raise IncompleteHardeningDefinition('\n'.join(missing))

    def __str__(self):
        return "%s description on host %s" % (self.name, self.host)

    def __repr__(self):
        return "<HardeningDescription: %s>" % self.name

    @classmethod
    def section(cls, section_class):
        """ This is the decorator that registers a Section class to a
        HardeningDescription. This has to be done for every sections child
        classes to be defined in the HardeningDescription.

        Look the example below:

        >>> class MyDescription(HardeningDescription):
        ...     pass
        ...
        >>> @MyDescription.section
        ... class SomeSection(Section):
        ...     pass
        ...
        >>>
        """
        attr = camelcase_to_underscore(section_class.__name__)
        setattr(cls, attr, section_class())
        return section_class

    @classmethod
    def sections_names(cls):
        """ Returns a list of the available section names for this description.
        """
        section_classes = []
        for attr_name in dir(basesections):
            attr = getattr(basesections, attr_name)
            if not inspect.isclass(attr):
                continue
            if issubclass(attr, Section) and attr != Section:
                if attr.has_topics():
                    section_classes.append(attr)
        name = lambda c: c.__name__.replace('Base', '')
        cu = lambda c: camelcase_to_underscore(name(c))
        return [(cu(c), name(c)) for c in section_classes]

    @property
    def sections(self):
        """ Returns a list of sections objects.
        """
        return [getattr(self, t[0]) for t in self.sections_names()]

    def check_failed_topics(self):
        """ In case any of the topics of the sections is empty, it raises the
        exception FailedOrIncompleteTopicsException.
        """
        failed_topics = reduce(lambda a, b: a + b,
           [[t[1] for t in s.topics if t[1].error or t[1].unhandled_error]
            for s in self.sections], [])
        incomplete_topics = reduce(lambda a, b: a + b,
           [[t[1] for t in s.topics if t[1].is_defined() and
             t[1].is_incomplete()] for s in self.sections], [])
        no_hardener_implemented_topics = reduce(lambda a, b: a + b,
           [[t[1] for t in s.topics if t[1].is_defined() and
             not t[1].is_hardener_implemented()] for s in self.sections], [])
        if failed_topics or incomplete_topics or \
                no_hardener_implemented_topics:
            raise FailedOrIncompleteTopicsException(failed_topics,
                                                    incomplete_topics,
                                                no_hardener_implemented_topics)

