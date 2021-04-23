#!/usr/bin/env python3

import git
import sys
import json
import requests
import os
import re

def main():
    # TODO: Use a getopt library
    git_cache = sys.argv[1]

    # This data looks like introduced,version,fixed,version
    issue_data = sys.argv[2]
    issue_array = issue_data.split(',')

    introduced_hash = issue_array[0]
    introduced_version = issue_array[1]
    fixed_hash = issue_array[2]
    fixed_version = issue_array[3]

    # For now assume this is up to date
    repo = git.Repo(git_cache)
    commit = repo.commit(issue_array[2])
    commit_message = commit.message
    commit_title = commit_message.splitlines()[0]

    # Verify some things
    check_commit = repo.commit(introduced_hash)
    check_version = re.search(r'(v\d+\.\d+\.\d+)\~', check_commit.name_rev)
    if check_version.groups()[0] != introduced_version:
        print("There is an introduced version mismatch")
        sys.exit(1)

    check_commit = repo.commit(fixed_hash)
    check_version = re.search(r'(v\d+\.\d+\.\d+)\~', check_commit.name_rev)
    if check_version.groups()[0] != fixed_version:
        print("There is a fixed version mismatch")
        sys.exit(1)

    # Open the issue
    json_data = {
        "vendor_name": "Linux",
        "product_name": "Kernel",
        "product_version": f"versions from {introduced_version} to before {fixed_version}",
        "vulnerability_type": "unspecified",
        "affected_component": "unspecified",
        "attack_vector": "unspecified",
        "impact": "unspecified",
        "credit": "",
        "references": [
            f"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id={introduced_hash}",
            f"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id={fixed_hash}"
        ],
        "reporter": "joshbressers",
        "reporter_id": 1692786,
        "notes": "",
        "description": f"{commit_title}\n\nThis is an automated ID intended to aid in discovery of potential security vulnerabilities. The actual impact and attack plausibility have not yet been proven.\nThis ID is fixed in Linux Kernel version {fixed_version} by commit {fixed_hash}, it was introduced in version {introduced_version} by commit {introduced_hash}. For more details please see the references link."
    }

    json_output = json.dumps(json_data, indent=2)


    repo = os.environ['GH_REPO']
    auth = (os.environ['GH_USERNAME'], os.environ['GH_TOKEN'])
    body = {
        "title": "DWF Request",
        "body": f"```\n--- DWF JSON ---\n{json_output}\n--- DWF JSON ---\n```",
        "labels": ["new", "check"]
    }
    headers = { "accept": "application/json" }

    resp = requests.post(f"https://api.github.com/repos/{repo}/issues",
json=body, auth=auth, headers=headers)
    resp.raise_for_status()

    issue_id = resp.json()["number"]
    print(f"Filed issue #{issue_id}")

if __name__ == "__main__":
	main()
