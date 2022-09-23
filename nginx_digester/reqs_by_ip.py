import datetime

from line_parser import LogLineParser, INTERNAL_DT_FORMAT


class ReqByIP(LogLineParser):
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
        self.by_ip: dict[str, list] = {}
        self.ignored_ips: set[str] = ignored_ips
        for line in lines:
            self.index_line_by_ip(line)

    def index_line_by_ip(
            self,
            line: str):
        """
        :param line: what gets processed.
        :param ignored_ips: ignore IPs we know and trust are only executing tests.
        :return:
        """
        finds = self.find_ip_and_timestamp(line)
        if finds is None or finds[0] in self.ignored_ips:
            return
        self.by_ip.setdefault(finds[0], []).append([finds[1]])
        self.append_rest_of_line(self.by_ip[finds[0]][-1], line, finds[2])

    @staticmethod
    def most_requests(req_dict):
        sorted_keys = sorted(req_dict.keys(), key=lambda x: len(req_dict[x]))
        return sorted_keys

    @staticmethod
    def count_failures_from_dict(req_dict):
        fails_per_ip = {ip: sum([1 for req in reqs if 400 <= req[2] < 500]) for
                        ip, reqs in req_dict.items()}
        return fails_per_ip

    @staticmethod
    def filter_between_times(req_dict: dict[str, list],
                             lower_dt: datetime,
                             upper_dt: datetime):
        filter_reqs = {ip: [
            req for req in reqs if lower_dt <= datetime.datetime.strptime(
                req[0], INTERNAL_DT_FORMAT) <= upper_dt]
            for ip, reqs in req_dict.items()}
        return filter_reqs

    @staticmethod
    def filter_dict_between_status_code(req_dict: dict[str, list],
                                        min_code: int,
                                        max_code: int):
        return {ip: [req for req in reqs if min_code <= req[2] <= max_code]
                for ip, reqs in req_dict.items()}
