import datetime
import time
from unittest.mock import Mock

import pytest

from main import KNOWN_FRIENDLY_TESTERS
from native_list import ChronoReqs, LogLineParser


@pytest.mark.parametrize("bit_after_time,expected_list", [
    ('"GET / HTTP/1.1" 404 153 "-" "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)" "-"',
     [["GET", "/", "HTTP/1.1"], 404, 153, "-", "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", "-"]),
    (r'"YOYO\x22 DA RUAN\x22 YANKA" 400 157 "-" "-" "-"',
     [[r"YOYO\x22", "DA", r"RUAN\x22", "YANKA"], 400, 157, "-", "-", "-"]),
    ('"" 400 0 "-" "-"',
     [[], 400, 0, "-", "-"])
])
def test_tokenise_line_variables(bit_after_time,expected_list):
    fake_instance = Mock(ChronoReqs)
    fake_instance.req_list = []
    fake_instance.ignored_ips = set()
    fake_instance.find_ip_and_timestamp = LogLineParser.find_ip_and_timestamp
    fake_instance.append_rest_of_line = LogLineParser.append_rest_of_line
    line = '44.44.44.44 - - [19/Sep/2022:08:01:21 +0000] ' + bit_after_time
    ChronoReqs.tokenise_line(fake_instance, line)
    req = fake_instance.req_list[0]
    assert req[0] == "220919 080121"
    assert req[1] == "44.44.44.44".rjust(16)
    for i in range(len(expected_list)):
        assert req[2 + i] == expected_list[i]



def test_chronological_requests():
    lines = r'''80.94.92.239 - - [19/Sep/2022:18:25:50 +0000] "GET / HTTP/1.1" 404 555 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36 Edg/90.0.818.46" "-"
216.244.66.203 - - [19/Sep/2022:18:43:20 +0000] "GET /robots.txt HTTP/1.1" 301 169 "-" "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot; help@moz.com)" "-"
159.89.170.59 - - [19/Sep/2022:18:52:55 +0000] "\x89%\xC3\xBAxgx\x90\x15H\xF4n7\xD4\x9Cm" 400 157 "-" "-" "-"
159.89.170.59 - - [19/Sep/2022:18:52:57 +0000] "\x16\x03\x01\x00{\x01\x00\x00w\x03\x03\xEB\x04\xFC\x10\xFA\x8B\x89\x1F\xC0\x13\xE4\x1E\x0F\xDD\xD7\xE8\xD9\xE0p\xE3\x92\xFF8\xA6\xBE}\x03X\xBAg\x12L\x00\x00\x1A\xC0/\xC0+\xC0\x11\xC0\x07\xC0\x13\xC0\x09\xC0\x14\xC0" 400 157 "-" "-" "-"
159.89.170.59 - - [19/Sep/2022:18:52:57 +0000] "\x16\x03\x01\x00{\x01\x00\x00w\x03\x03\x8B\xD0\xEF\xC6\xBEo+\xEF" 400 157 "-" "-" "-"
159.89.170.59 - - [19/Sep/2022:18:52:57 +0000] "GET / HTTP/1.1" 404 153 "-" "Mozilla/5.0 zgrab/0.x" "-"
152.89.196.211 - - [19/Sep/2022:19:31:42 +0000] "GET /actuator/gateway/routes HTTP/1.1" 404 555 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36" "-"
44.44.44.44 - - [19/Sep/2022:20:06:47 +0000] "\x16\x03\x01\x02\x00\x01\x00\x01\xFC\x03\x03d+\xB6\xDE\x8D\x10\xDD5@1\xE3\x8ET\xFD\x10\xE8\xF5>x\xBF\x7F\x7F\xFE\x16" 400 157 "-" "-" "-"
103.131.71.96 - - [19/Sep/2022:20:08:09 +0000] "GET /robots.txt HTTP/1.1" 301 169 "-" "Mozilla/5.0 (compatible; coccocbot-web/1.0; +http://help.coccoc.com/searchengine)" "-"
44.44.44.44 - - [19/Sep/2022:20:14:38 +0000] "YOYO\x22 DA RUAN\x22 YANKA" 400 157 "-" "-" "-"'''
    chrono_reqs = ChronoReqs(lines, KNOWN_FRIENDLY_TESTERS)
    ips = [x[1] for x in chrono_reqs.req_list]
    assert ips == [x.split()[0].rjust(16) for x in lines.split("\n")]
    for line in chrono_reqs.req_list:
        assert len(line) == 8
    print(chrono_reqs.req_list)


def test_requests_per_period():
    chrono_reqs = ChronoReqs(open("access.log").read(), KNOWN_FRIENDLY_TESTERS)
    t0 = time.time()
    bucket_starts, bucketed_reqs = ChronoReqs.requests_per_period(chrono_reqs.req_list, datetime.timedelta(hours=2))
    t1 = time.time()
    print("per period took {:.04f}".format(t1 - t0))


def test_failures_per_5m_period():
    chrono_reqs = ChronoReqs(open("access.log").read(), KNOWN_FRIENDLY_TESTERS)
    t0 = time.time()
    bucket_starts, bucketed_fails = chrono_reqs.failures_per_period(datetime.timedelta(minutes=5))
    t1 = time.time()
    fails_per_period = {x[0]: len(x[1]) for x in zip(bucket_starts, bucketed_fails)}
    print("per period took {:.04f}".format(t1 - t0))


def test_failures_per_1hr_period():
    chrono_reqs = ChronoReqs(open("access.log").read(), KNOWN_FRIENDLY_TESTERS)
    t0 = time.time()
    bucket_starts, bucketed_fails = chrono_reqs.failures_per_period(datetime.timedelta(hours=1))
    t1 = time.time()
    fails_per_period = {x[0]: len(x[1]) for x in zip(bucket_starts, bucketed_fails)}
    print("per period took {:.04f}".format(t1 - t0))



