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

    dwf_data = the_data["dwf"]

    # We will do something special for the kernel
    if dwf_data["vendor_name"] == "Linux" and \
        dwf_data["product_name"] == "Kernel":

        # Grab the first line
        summary = dwf_data["description"].split('\n')[0]
        the_data["OSV"]["summary"] = summary
        the_data["OSV"]["details"] = dwf_data["description"]

    else:
        # Everything not the kernel we will construct a simple summary
        vuln_type = dwf_data["vulnerability_type"]
        name = dwf_data["product_name"]
        version = dwf_data["product_version"]

        summary = f"{vuln_type} in {name} version {version}"
        the_data["OSV"]["summary"] = summary
        the_data["OSV"]["details"] = dwf_data["description"]

    the_time =  datetime.datetime.utcnow().isoformat() + "Z"
    the_data["OSV"]["modified"] = the_time

    # Write file and add to commit
    dwf_repo.update_id(i, the_data)

dwf_repo.commit("Update OSV summary")
dwf_repo.push()
