import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest

import DWF

class FakeIssue:

	def __init__(self):
		self.dwf = "CAN-1900-0001"
		self.id = 1
		self.json = {
			"vendor_name": "test vendor",
			"product_name": "test product",
			"product_version": "test version",
			"vulnerability_type": "test type",
			"affected_component": "test component",
			"attack_vector": "test vector",
			"impact": "test impact",
			"credit": "test credit",
			"references": [
				"http://example.com"
			],
			"reporter": "joshbressers",
			"reporter_id": 1692786,
			"notes": "test note",
			"description": "test description"
		}

	def get_dwf_json(self):
		return self.json

	def get_reporter(self):
		return "%s:%s" % (self.json['reporter'], self.json['reporter_id'])

	def get_dwf_id(self):
		return self.dwf

	def ugly_json(self):
		# I'm not even sorry
		return {'dwf': {'vendor_name': 'test vendor', 'product_name': 'test product', 'product_version': 'test version', 'vulnerability_type': 'test type', 'affected_component': 'test component', 'attack_vector': 'test vector', 'impact': 'test impact', 'credit': 'test credit', 'references': ['http://example.com'], 'reporter': 'joshbressers', 'reporter_id': 1692786, 'notes': 'test note', 'description': 'test description'}, 'data_type': 'CVE', 'data_format': 'MITRE', 'data_version': '4.0', 'CVE_data_meta': {'ASSIGNER': 'dwf', 'ID': 'CVE-1900-0001', 'STATE': 'PUBLIC'}, 'affects': {'vendor': {'vendor_data': [{'vendor_name': 'test vendor', 'product': {'product_data': [{'product_name': 'test product', 'version': {'version_data': [{'version_value': 'test version'}]}}]}}]}}, 'problemtype': {'problemtype_data': [{'description': [{'lang': 'eng', 'value': 'test type'}]}]}, 'references': {'reference_data': [{'url': 'http://example.com', 'refsource': 'MISC', 'name': 'http://example.com'}]}, 'description': {'description_data': [{'lang': 'eng', 'value': 'test description'}]}}
		# Maybe a little sorry

class TestDWFRepo(unittest.TestCase):

	def setUp(self):
		self.repo = DWF.DWFRepo("https://github.com/distributedweaknessfiling/dwflist.git", testing=True)

	def tearDown(self):
		self.repo.close()

	def testApprovedUser(self):
		self.assertTrue(self.repo.approved_user("joshbressers:1692786"))
		self.assertFalse(self.repo.approved_user("baduser"))

	def testAddDWF(self):
		# This test is really weak
		fake_issue = FakeIssue()
		the_id = self.repo.add_dwf(fake_issue)
		self.assertTrue(the_id.startswith('CVE'))

	def testCanToDWF(self):
		fake_issue = FakeIssue()
		fake_issue.json["reporter"] = "bad_user"
		the_id = self.repo.add_dwf(fake_issue)
		fake_issue.dwf = the_id
		the_id = self.repo.can_to_dwf(fake_issue)
		self.assertEqual(the_id[3:], fake_issue.dwf[3:])

	def testPush(self):
		# Probably never test this one unless we setup a demo repo
		pass

	def testNextDWFPath(self):
		# We really need a clean repo
		the_id = self.repo.get_next_dwf_path()
		self.assertTrue(the_id[0].startswith('CAN'))
		the_id = self.repo.get_next_dwf_path(approved_user = True)
		self.assertTrue(the_id[0].startswith('CVE'))

	def testGetDWFJSON(self):
		self.maxDiff = None
		fake_issue = FakeIssue()
		the_data = self.repo.get_dwf_json_format('CVE-1900-0001', fake_issue.get_dwf_json())
		for i in fake_issue.get_dwf_json().keys():
			# Let's just check the keys
			self.assertTrue(i in the_data['dwf'])
