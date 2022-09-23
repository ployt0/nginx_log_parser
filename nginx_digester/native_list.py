"""
This form of log storage was **much** faster for time slicing than reqs_by_ip,
ie. having requests indexed by IP.
"""

import datetime

from line_parser import LogLineParser, INTERNAL_DT_FORMAT


class ChronoReqs(LogLineParser):
    def __init__(
            self,
            instr: str,
            ignored_ips: set[str],
    ):
        """
        :param instr: log dump to process
        :param ignored_ips: ignore IPs we know and trust are only executing tests.
        :return:
        """
        lines = instr.split("\n")
        self.req_list: list[list] = []
        self.ignored_ips: set[str] = ignored_ips
        for line in lines:
            self.tokenise_line(line)

    def tokenise_line(self, line: str):
        """
        :param line: what gets processed.
        :return:
        """
        finds = self.find_ip_and_timestamp(line)
        if finds is None or finds[0] in self.ignored_ips:
            return
        self.req_list.append([finds[1], finds[0].rjust(16)])
        self.append_rest_of_line(self.req_list[-1], line, finds[2])

    @staticmethod
    def get_failures(req_list):
        return [req for req in req_list if 400 <= req[3] < 500]

    @staticmethod
    def to_dict(req_list):
        return {x[1] : [x[0], *x[2:]] for x in req_list}

    @staticmethod
    def requests_per_period(req_list: list[list], period: datetime.timedelta) \
            -> tuple[list[datetime], list[list]]:
        date_cursor = datetime.datetime.strptime(
            req_list[0][0], INTERNAL_DT_FORMAT)
        upper_dt = datetime.datetime.strptime(
            req_list[-1][0], INTERNAL_DT_FORMAT)
        list_curs = 0
        bucketed_reqs = []
        bucket_starts = []
        while date_cursor < upper_dt:
            cursor_limit = date_cursor + period
            bucket = []
            while datetime.datetime.strptime(
                    req_list[list_curs][0], INTERNAL_DT_FORMAT
            ) < cursor_limit:
                bucket.append(req_list[list_curs])
                list_curs += 1
                if list_curs == len(req_list):
                    break
            bucketed_reqs.append(bucket)
            bucket_starts.append(date_cursor)
            date_cursor = cursor_limit
        return bucket_starts, bucketed_reqs

    @staticmethod
    def filter_by_status(req_list, min_code: int, max_code: int):
        return [req for req in req_list if min_code <= req[3] <= max_code]

    def failures_per_period(self, period: datetime.timedelta):
        fail_list = ChronoReqs.filter_by_status(self.req_list, 400, 499)
        bucket_starts, bucketed_fails = ChronoReqs.requests_per_period(
            fail_list, period)
        return bucket_starts, bucketed_fails

