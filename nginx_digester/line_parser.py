import datetime
import re
from typing import Optional

ip_matcher = re.compile(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}")
example_dt = "[01/Sep/2022:23:09:56 +0000]"
INTERNAL_DT_FORMAT = "%y%m%d %H%M%S"


class LogLineParser:
    @staticmethod
    def append_rest_of_line(list_target, line, curs) -> None:
        """
        :param list_target: what we append *to*
        :param line: what we read *from*
        :param curs: should be just after the opening quote for the string after
            ip and time.
        :return: None
        """
        close_qt = line.find('"', curs)
        # Attempts to inject quotes here are escaped as \x22.
        if close_qt == -1:
            return
        action_addy_proto = line[curs:close_qt].split()
        list_target.append(action_addy_proto)
        curs = close_qt + 2
        code, bytes_returned = map(int, line[curs:].split(" ")[0:2])
        list_target.extend([code, bytes_returned])
        # Add: referrer, user_agent, x_forwarded_for:
        for _ in range(3):
            curs = line.find('"', curs + 1)
            if curs == -1:
                break  # break if there were only 2 fields after size.
            close_qt = line.find('"', curs + 1)
            list_target.append(line[curs + 1: close_qt])
            curs = close_qt

    @staticmethod
    def find_ip_and_timestamp(line: str) -> Optional[tuple[str, str, int]]:
        """
        Finds the IP and timestamp
        :param line:
        :return: On success the 3-tuple of ip, datetime, cursor_position
        """
        matches = ip_matcher.match(line)
        if not matches:
            # docker logs appears to mix in debug/error entries, ie it's not pure
            # access logging. These don't have an IP.
            return
        ip = matches.group(0)
        curs = len(ip) + 5
        # Temp column, Supposedly is "remote user" but never seen. Always " - - "
        remote_user = line[len(ip):len(ip) + 5]
        date_str = line[curs:curs + len(example_dt)]
        if date_str[0] == "[" and date_str[-1] == "]":
            # check parsing
            dt = datetime.datetime.strptime(
                date_str[1:-1], "%d/%b/%Y:%H:%M:%S %z").astimezone(
                datetime.timezone.utc)
            return ip, dt.strftime(INTERNAL_DT_FORMAT), curs + len(
                example_dt) + 2
        else:
            return
