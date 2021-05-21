# Module for querying the NVD CVE API
#

import datetime

class CVE:

    def __init__(self, json):
        self.data = json
