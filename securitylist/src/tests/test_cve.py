#!/usr/bin/env python

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest

import securitylist
import tempfile
import os
import json

class TestCVE(unittest.TestCase):

    def setUp(self):
        # setup temp path
        self.tempdir = tempfile.TemporaryDirectory()
        securitylist.CVE.path = self.tempdir.name

        # Read test json
        with open('src/tests/nvd.json') as fh:
            self.json_data = json.load(fh)

        self.one_id = self.json_data["result"]["CVE_Items"][0]

    def tearDown(self):
        # Teardown temp path
        self.tempdir.cleanup()

    def test_read(self):
        # Write the test json
        the_id = self.one_id['cve']['CVE_data_meta']['ID']
        c = securitylist.CVE(the_id, self.one_id)
        c.write()

        # Now let's read it back in
        c = securitylist.CVE(the_id)
        self.assertEqual(c.id, the_id)

        # Try to read a bad ID, catch the exception
        with self.assertRaises(Exception):
            securitylist.CVE("CVE-1492-0001")

    def test_write(self):
        the_id = self.one_id['cve']['CVE_data_meta']['ID']
        c = securitylist.CVE(the_id, self.one_id)
        c.write()

        # check path for file
        self.assertTrue(os.path.exists(c.get_filename()))
