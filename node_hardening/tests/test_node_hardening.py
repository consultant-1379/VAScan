#!/usr/bin/env python
import re

from node_hardening.hardening import HardeningProcessor
from node_hardening.descriptions.litp.ms import MsDescription
from sshmock import SshScpClientMock

from unittest import TestCase


class TestMsNodeHardening(TestCase):

    def setUp(self):
        description = MsDescription('MS')
        self.processor = HardeningProcessor('litp', description, '', '', '')
