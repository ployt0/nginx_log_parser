"""
This form of log storage was **much** faster for time slicing than reqs_by_ip,
ie. having requests indexed by IP.
"""

import datetime
import ipaddress
import re
from collections import Counter

import requests

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

    @staticmethod
    def failures_per_period(req_list, period: datetime.timedelta)\
            -> tuple[list[datetime], list[list]]:
        fail_list = ChronoReqs.filter_by_status(req_list, 400, 499)
        bucket_starts, bucketed_fails = ChronoReqs.requests_per_period(
            fail_list, period)
        return bucket_starts, bucketed_fails

    @staticmethod
    def get_paths(req_list: list[list]) -> Counter:
        """
        :param req_list: may be member, or already filtered.
        :return: Counter, call `.most_common(20)` for 20 most common paths.
        """
        return Counter(req[2][1] for req in req_list if len(req[2]) > 2)

    @staticmethod
    def get_reqs_matching(path_match: str, req_list: list[list]) -> list[list]:
        return [req for req in req_list if
                len(req[2]) > 2 and re.match(path_match, req[2][1])]

    @staticmethod
    def divide_reqs_by_path_prefixes(prefix_dict: dict[str, list], req_list: list[list]):
        """
        Divide requests between mutually exclusive path prefixes. If not
        mutually exclusive the first will match.

        :param prefix_dict: indexed by path prefixes. Mostly mutually exclusive.
            Since python 3.7 key order is guaranteed. We may include a fallback
            as the final element. Caller to initialise values to empty lists.
        :param req_list: list of requests.
        :return: any requests that weren't matched.
        """
        unmatched = []
        for req in req_list:
            if len(req[2]) > 2:
                for k in prefix_dict.keys():
                    if req[2][1].startswith(k):
                        prefix_dict[k].append(req)
                        break
                else:
                    unmatched.append(req)
        return unmatched

    @staticmethod
    def find_unusual_meth_path_protos(req_list: list[list]) -> list[list]:
        # These appear very suspicious. Logins, miners, rpc... Sus.
        # Block if enough volume.
        return [req for req in req_list if len(req[2]) > 3]

    @staticmethod
    def remove_googlebot(req_list: list[list]) -> list[list]:
        res = requests.get("https://developers.google.com/static/search/apis/ipranges/googlebot.json")
        prefixes = res.json()["prefixes"]
        cidrs = [ipaddress.ip_network(d["ipv4Prefix"]) for d in prefixes if "ipv4Prefix" in d]
        return [x for x in req_list if not any(
            ipaddress.ip_address(x[1].strip()) in cidr
            for cidr in cidrs)]



# todo add graphing by period, by status code, all bucketed, probably.
# todo check, and graph, paths now that nginx is denying the main offenders.