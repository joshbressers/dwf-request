# Module for querying the NVD CVE API
#

import requests
import datetime

class UnexpectedResults(Exception):
    pass

class NVD:

    def __init__(self):
        self.now = datetime.datetime.utcnow()
        self.total = 0

    def __get_time__(self, ts):
        # Return the time format the API wants

        y = ts.year
        m = ts.month
        d = ts.day
        h = ts.hour
        mi = ts.minute
        s = ts.second

        return f"{y}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}:000 UTC-00:00"

    def get_range(self, start, end):

        if start is None:
            self.start_time = '1990-01-01T00:00:00:000 UTC-00:00'

        if end is None:
            self.end_time = self.__get_time__(self.now)

        nvd_url = "https://services.nvd.nist.gov/rest/json/cve/1.0"

        payload = {
            "startIndex": 0,
            "resultsPerPage": 5000,
            "modStartDate": self.start_time,
            "modEndDate": self.end_time
        }

        response = requests.get(nvd_url, params=payload)
        response.raise_for_status()
        self.data = response.json()

        self.total = self.data["totalResults"]
