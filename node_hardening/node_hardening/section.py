import re
from copy import copy
from utils import camelcase_to_underscore


class MissingTopic(Exception):
    """ This exception should be raised in case a topic is missing from the
    section. The topics are previously defined in a base Section class. If
    the child class doesn't define a value for it, this exception will be
    raised.
    """

    def __init__(self, topics):
        """ It gets a list of topics and builds the error message.
        """
        super(MissingTopic, self).__init__(str(topics))
        self.topics = topics
        self.message = "The following topics are missing: %s" % \
                       ', '.join(topics)


class WrongTopic(Exception):
    """ This exception should be raised in case a topic is mistakenly defined
    in a section. The topics are previously defined in a base Section class. If
    the child class define an attribute that is not defined on the base, this
    exception will be raised.
    """

    def __init__(self, section_name, topics):
        """ It gets the section name and a list of topics and builds the error
        message.
        """
        super(WrongTopic, self).__init__(str(topics))
        self.topics = topics
        self.message = "The following topics are invalid for the %s " \
                       "section: %s" % (section_name, ', '.join(topics))


class WrongTopicType(Exception):
    """ This exception should be raise when an expected_value is set to a topic
    with a different type that it should be.
    """


class WrongTopicsTypes(Exception):
    """ This exception should be raised in case there are topics defined in the
    child description with wrong types. The topics are previously defined in a
    base Section class with a proper "type" specified. If the child class
    assign a value for that topic with a different type that it should be, this
    exception will be raised.
    """

    def __init__(self, topics):
        """ It gets a list of topics and builds the error message.
        """
        super(WrongTopic, self).__init__(str(topics))
        self.topics = topics
        self.message = "The following topics contains wrong type: %s" % \
                      ', '.join(["%s: must be %s" % (a, v) for a, v in topics])


class CommandExecutionException(Exception):
    """ This exception is raised every time a command execution return a status
    code different than zero.
    """

    def __init__(self, message, output, status_code):
        """ This constructor also requires the status code to be able to be
        retrieved after the "except" statement.
        """
        super(CommandExecutionException, self).__init__(message)
        self.output = output
        self.status_code = status_code


class NullExpectedValue(object):
    """ This class is just the initial value for the expected_value in the
    Topic. It's just used to be verified in the MetaSection meta class whether
    the "expected_value" was properly defined in the Topic child class or not.
    """


class Topic(object):
    """ This is the topic class that represents each attribute of a Section
    class.
    """

    bool_choices_sub_regex = re.compile(r"(.*)\<\w*\|\w*\>(.*)")
    bool_choices_regex = re.compile(r".*\<(\w*)\|(\w*)\>.*")

    def __init__(self, _type, _desc=None):
        """ The builds an instance, a _type is required. This argument must be
        any "type" in Python. The _desc argument is just a brief description
        to be include in the report for this topic.

        The first instance of a topic contains a null value for the
        _expected_value. It will be properly valued by the child Section
        section when the MetaSection meta class injects it.
        """
        self._expected_value = NullExpectedValue()
        self._type = _type
        self.name = None
        self._desc = _desc
        self.outputs = []
        self.check_outputs = []
        self.harden_outputs = []
        self.double_check_outputs = []
        self.report = None
        self.error = ""
        self.unhandled_error = ""
        self.checked_and_hardened = False
        self.just_report = False
        self.hardener_implemented = False
        self.harden_case_not_implemented = False
        self.retrieved_value = None
        self.ssh_runner = None

    def __str__(self):
        return str(self.name)

    def __repr__(self):
        return "<Topic: %s>" % str(self)

    @property
    def expected_value(self):
        return self._expected_value

    @expected_value.setter
    def expected_value(self, value):
        """ This setter also checks if the type of the value is actually
        correct, and raise the WrongTopicType exception in case it is not.
        """
        if not isinstance(value, self._type):
            raise WrongTopicType("expected_value must be an instance of %s" %
                                 self._type)
        self._expected_value = value

    @property
    def description(self):
        """ It just returns the brief description defined on the _desc member.
        In case this topic has the _type == bool, the brief description might
        be dynamically different and it uses the regular expressions to replace
        the terms according to the expected_value.
        """
        if self._type == bool:
            match = self.bool_choices_regex.match(self._desc)
            if not match:
                return self._desc
            pos, neg = match.groups()
            sub = self.bool_choices_sub_regex.sub(r"\1 %s \2", self._desc)
            return sub % pos if self.expected_value else sub % neg
        else:
            return self._desc

    def is_defined(self):
        """ If the expected_value is an instance of WrongTopicType, it means
        that this topic is not actually defined yet, just instantiated.
        """
        return not isinstance(self.expected_value, NullExpectedValue)

    def is_incomplete(self):
        """ If the report is empty and there's no errors occurred.
        """
        return not self.report and not self.error and not self.unhandled_error

    def is_hardener_implemented(self):
        """ If the hardener class is implemented/executed.
        """
        return self.hardener_implemented



class MetaSection(type):
    """ This meta class manipulates the attributes in the Section class
    depending on the level of the inheritance.
    """

    def __new__(mcs, name, bases, attrs):
        """ In case the class is a Section base but it is not the Section class
        itself, the attributes are manipulated. A base Section class must have
        defined only Topic attributes. The child class of a base Section can
        override those attributes with normal values and this metaclass will
        get the Topic instance from the base class class and set the value
        in the "expected_value" attribute of the topic and the attribute
        of the child Section class will be transformed back to the Topic
        instance as it was in the base class, but now with the expected_value
        properly specified.
        
        This metaclass also do some checks and raise exceptions in case it 
        validates that the child classes are not properly created. The
        validation includes:
         - missing topics: the attributes defined in the base Section class as
                           a Topic instance *must* be overridden in the child
                           Section class, if not, a MissingTopic exception is
                           raised.
         - wrong topic types: the attributes defined in the child section class
                            must have a correct value type as the specified in
                            the Topic instance of the base Section class.
         - wrong topics: if an attribute defined in the child Section class
                         is not defined as a Topic instance in the base
                         Section, the WrongTopic exception is raised.
        """
        new_attrs = attrs.copy()
        is_section_based = False
        try:
            is_section_based = issubclass(bases[0], Section) and \
                               bases[0] != Section
        except NameError:
            pass
        if is_section_based:
            # list of topics to be listed if the validation fails
            missing = []
            wrong_types = []
            wrong_topics = []
            for attr, value in attrs.items():
                if attr.startswith('__'):
                    # just ignores mangling and reserved Python attributes
                    continue
                if isinstance(value, Topic) and \
                   isinstance(value.expected_value, NullExpectedValue):
                    # if the expected_value of the topic is an instance of
                    # NullExpectedValue, it means that it is missing from the
                    # definition in the child class
                    missing.append(attr)
                    continue
                base_topic = getattr(bases[0], attr, None)
                if base_topic is None:
                    # if the base class doesn't have the same attribute
                    # defined, it means that it's wrong. Sections doesn't allow
                    # exclusive attributes.
                    wrong_topics.append(attr)
                    continue
                base_topic.name = attr
                # makes a copy of the base_topic instance to be used in the
                # child class.
                topic = copy(base_topic)
                try:
                    # populates the value taken from the child Section class to
                    # the new topic instance "copied" from the base class, to
                    # be used later on to override the attribute.
                    topic.expected_value = value
                except WrongTopicType:
                    # in case the value set in the attribute of child class is
                    # of a not expected type.
                    wrong_types.append((attr, topic._atype))
                    continue
                # in case every validation passes, the new_attrs dictionary
                # overrides the current attribute with the Topic instance from
                # the base with the expected_value properly populated.
                new_attrs[attr] = topic

            if missing:
                raise MissingTopic(missing)
            if wrong_types:
                raise WrongTopicType(wrong_types)
            if wrong_topics:
                raise WrongTopic('', wrong_topics)

        return super(MetaSection, mcs).__new__(mcs, name, bases, new_attrs)


class Section(object):
    """ This is the class that defines a section in a Node Hardening
    description. It also should correspond to a Section in the final Report.
    Every section class attribute is known as a Topic, so its values must be
    Topic instances.

    The first child class based on this Section class must define the Topic
    instances specifying the type of the topic, e.g:

    >>> class BaseSomeSection(Section):
    ...     some_topic = Topic(str)
    ...     some_other_topic = Topic(list)
    ...
    >>>

    A section child must inherit from a base section with the topic previously
    defined, e.g.:

    >>> class SomeSection(BaseSomeSection):
    ...     some_topic = "some string value"
    ...     some_other_topic = ["a", "list", "of", "things"]
    ...
    >>> SomeSection.some_topic
    <Topic: some_topic>
    >>> SomeSection.some_topic.expected_value
    'some string value'

    The class above, inherited from the BaseSomeSection, overrides the 2
    attributes with simple values. Those attributes are manipulated in the
    execution time by the metaclass MetaSection and the values are set to the
    "expected_value" attribute in the Topic instances copied from the base and
    then the topic copy is set back to the current child class SomeSection,
    before the class SomeSection is actually created.
    """
    __metaclass__ = MetaSection

    def __str__(self):
        return self.title

    def __repr__(self):
        return '<Section: %s>' % str(self)

    @property
    def title(self):
        """ It just return a friendly title based on the class name.
        """
        und = camelcase_to_underscore(self.__class__.__name__)
        return und.replace('_', ' ').capitalize()

    @property
    def topics(self):
        """ Return a list of tuples containing the topic name and the topic
        instance of this Section. It uses reflection to get those attributes.
        The topic must be defined in the Section, it means, it has the
        expected_value properly set.
        """
        return [(i, getattr(self, i)) for i in dir(self)
                if i != 'topics' and
                   isinstance(getattr(self, i), Topic) and
                   getattr(self, i).is_defined()]

    @classmethod
    def has_topics(cls):
        """ In case the section class has no topics attributes, this method
        returns False.
        """
        return bool([(i, getattr(cls, i)) for i in dir(cls)
                if i != 'topics' and
                   isinstance(getattr(cls, i), Topic)])

    @property
    def doc_string(self):
        """ Gets the doc string defined in the class. It searches in the bases
        util it finds it.
        """
        def _get_doc(klass):
            doc = klass.__doc__
            if not doc:
                return _get_doc(klass.__bases__[0])
            return doc
        return _get_doc(self.__class__)
