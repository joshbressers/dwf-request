#!/usr/bin/env python

import datetime
import pathlib
import DWF
import os

repo_name = os.environ['GH_REPO']
repo_url = "https://github.com/%s.git" % repo_name
username = os.environ['GH_USERNAME']

# Check out the repo

dwf_repo = DWF.DWFRepo(repo_url)

# Gather all the files

all_ids = dwf_repo.get_all_ids()

# Load data

for i in all_ids:
    print(i)
    the_data = dwf_repo.get_id(i)

    issue_data = the_data["dwf"]

    # If not namespace
    if "OSV" not in the_data:
        # This should never happen
        print("Something terrible has happened")
        print("Issue %s doesn't have OSV data" % i)
        sys.exit(1)
    else:

        if issue_data["vendor_name"] == "Linux" and \
           issue_data["product_name"] == "Kernel":
            # Only update kernel issues
            the_data["OSV"]["package"]["ecosystem"] = "Linux"

            the_time =  datetime.datetime.utcnow().isoformat() + "Z"
            the_data["OSV"]["modified"] = the_time

            # Write file and add to commit
            dwf_repo.update_id(i, the_data)

dwf_repo.commit("Update Kernel ecosystem")
dwf_repo.push()
