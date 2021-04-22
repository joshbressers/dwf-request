#!/usr/bin/env python3

import os
import re
import datetime
import time
import DWF

repo_name = os.environ['GH_REPO']
issues_url = "https://api.github.com/repos/%s/issues" % repo_name
repo_url = "https://github.com/%s.git" % repo_name
username = os.environ['GH_USERNAME']


def main():

	start_time = datetime.datetime.now()

	new_issues = DWF.get_new_issues(issues_url)
	can_issues = DWF.get_approved_can_issues(issues_url)

	if len(new_issues) > 0 or len(can_issues) > 0:

		# Only touch the repo if we have work to do
		dwf_repo = DWF.DWFRepo(repo_url)

		# Look for new issues
		for i in new_issues:

			if re.search('(CVE|CAN)-\d{4}-\d+', i.title):
				# There shouldn't be a CVE/CAN ID in the title, bail on this issue
				print("Found an ID in the title for issue %s" % i.id)
				continue

			if (i.creator != username):
				print("Issue %s is not created by %s" % (i.id, username))
				continue

			print("Updating issue %s" % i.id)
			dwf_id = dwf_repo.add_dwf(i)
			i.assign_dwf(dwf_id, dwf_repo.approved_user(i.get_reporter()))

		# Now look for approved CAN issues
		for i in can_issues:
			approver = i.who_approved()
			if dwf_repo.approved_user(approver):
				# Flip this to a DWF
				dwf_repo.can_to_dwf(i)
				i.can_to_dwf()
			else:
				print("%s is unapproved for %s" % (approver, i.id))

		dwf_repo.close()

	stop_time = datetime.datetime.now()
	total_time = stop_time - start_time
	total_seconds = total_time.total_seconds()

	if total_seconds < 10:
		# Things get weird if we die too early wtih docker-compose
		time.sleep(10 - total_seconds)
	
if __name__ == "__main__":
	main()
