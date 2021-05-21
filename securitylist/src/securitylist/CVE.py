# Module for querying the NVD CVE API
#

import json
import os
from pathlib import Path

class CVE:
    path = None

    def __init__(self, cve_id, the_json=None):
        self.id = cve_id

        if the_json is None:
            # We need to read in the json
            with open(self.get_filename()) as fh:
                self.json = json.load(fh)
        else:
            self.json = the_json

    def write(self):
        # Write the CVE content to a file

        filename = self.get_filename(create=True)

        with open(filename, 'w') as fh:
            fh.write(json.dumps(self.json))

    def get_filename(self, create=False):

        # The filename will look like
        # {self.path} / year / thousand_dir / {self.id}.json
        (year, just_id) = self.id.split('-')[1:]

        id_int = int(just_id)
        thousand_dir = "%dxxx" % int(id_int / 1000)

        the_path = os.path.join(self.path, year, thousand_dir)
        if create is True:
            Path(the_path).mkdir(parents=True, exist_ok=True)


        id_file = f"{self.id}.json"
        the_filename = os.path.join(the_path, id_file)

        return the_filename
