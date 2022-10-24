import datetime
import json
import time
from collections import Counter
from unittest.mock import Mock, patch

import pytest

from main import KNOWN_FRIENDLY_TESTERS
from native_list import ChronoReqs, LogLineParser
from requests import Response


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


@pytest.fixture(scope="module")
def chrono_reqs():
    return ChronoReqs(open("access.log").read(), KNOWN_FRIENDLY_TESTERS)


def test_requests_per_period(chrono_reqs):
    t0 = time.time()
    bucket_starts, bucketed_reqs = ChronoReqs.requests_per_period(
        chrono_reqs.req_list, datetime.timedelta(hours=2))
    t1 = time.time()
    print("per period took {:.04f}".format(t1 - t0))


def test_failures_per_5m_period(chrono_reqs):
    t0 = time.time()
    bucket_starts, bucketed_fails = ChronoReqs.failures_per_period(
        chrono_reqs.req_list, datetime.timedelta(minutes=5))
    t1 = time.time()
    fails_per_period = {x[0]: len(x[1]) for x in zip(bucket_starts, bucketed_fails)}
    print("per period took {:.04f}".format(t1 - t0))


def test_failures_per_1hr_period(chrono_reqs):
    t0 = time.time()
    bucket_starts, bucketed_fails = ChronoReqs.failures_per_period(
        chrono_reqs.req_list, datetime.timedelta(hours=1))
    t1 = time.time()
    fails_per_period = {x[0]: len(x[1]) for x in zip(bucket_starts, bucketed_fails)}
    print("per period took {:.04f}".format(t1 - t0))


def test_get_paths(chrono_reqs):
    cmn_paths = ChronoReqs.get_paths(chrono_reqs.req_list).most_common(10)
    expected_paths = [
        ('/xmlrpc.php', 4550),
        ('/', 1306),
        ('/wp/xmlrpc.php', 745),
        ('/wordpress/xmlrpc.php', 745),
        ('/old/xmlrpc.php', 745),
        ('/new/xmlrpc.php', 745),
        ('/blog/xmlrpc.php', 745),
        ('/feed/', 468),
        ('/static/js/menu_populators.js', 280),
        ('/static/js/common_utils.js', 276)]
    assert cmn_paths == expected_paths


def test_divide_reqs_by_path_prefixes(chrono_reqs):
    # These are just the most popular prefixes from the previous test.
    # Makes sense to try and aggregate requests under the paths of the most
    # common requests. Unless those paths were all already common. Feat. bloat.
    prefix_dict = {x: list() for x in [
        "/old/", "/new/", "/blog/", "/feed/",
        "/static/", "/wordpress/", "/wp/",
        "/"
    ]}
    unmatched = ChronoReqs.divide_reqs_by_path_prefixes(prefix_dict, chrono_reqs.req_list)
    assert len(unmatched) == 36


def test_find_unusual_meth_path_protos(chrono_reqs):
    # So unusual that I don't understand them. I can refer back to see if I've
    # blocked them later.
    req_list_fltrd = ChronoReqs.find_unusual_meth_path_protos(chrono_reqs.req_list)
    assert req_list_fltrd == [[
        '220910 183310', '    106.75.176.0',
        [
            '{\\x22params\\x22:', '[\\x22miner1\\x22,', '\\x22password\\x22],',
            '\\x22id\\x22:', '2,', '\\x22method\\x22:',
            '\\x22mining.authorize\\x22}'
        ], 400, 157, '-', '-'], [
        '220910 183311', '    106.75.176.0', [
            '{\\x22id\\x22:1,\\x22jsonrpc\\x22:\\x222.0\\x22,\\x22method\\x22:'
            '\\x22login\\x22,\\x22params\\x22:{\\x22login\\x22:\\x22blue1'
            '\\x22,\\x22pass\\x22:\\x22x\\x22,\\x22agent\\x22:\\x22Windows',
            'NT', '6.1;', 'Win64;', 'x64\\x22}}'
        ], 400, 157, '-', '-'], [
        '220910 183312', '    106.75.176.0', [
            '{\\x22params\\x22:', '[\\x22miner1\\x22,', '\\x22bf\\x22,',
            '\\x2200000001\\x22,', '\\x22504e86ed\\x22,',
            '\\x22b2957c02\\x22],', '\\x22id\\x22:', '4,', '\\x22method\\x22:',
            '\\x22mining.submit\\x22}'
        ], 400, 157, '-', '-'], [
        '220914 211725', '    45.148.120.0', [
            '{\\x22id\\x22:', '1,', '\\x22method\\x22:',
            '\\x22mining.subscribe\\x22,', '\\x22params\\x22:',
            '[\\x22cpuminer/2.5.1\\x22]}'
        ], 400, 157, '-', '-'], [
        '220914 211727', '    45.148.120.0', [
            '{\\x22id\\x22:', '1,', '\\x22method\\x22:',
            '\\x22mining.subscribe\\x22,', '\\x22params\\x22:',
            '[\\x22MinerName/1.0.0\\x22,', '\\x22EthereumStratum/1.0.0\\x22]}'
        ], 400, 157, '-', '-'], [
        '220914 211728', '    45.148.120.0', [
            '{\\x22id\\x22:1,\\x22jsonrpc\\x22:\\x222.0\\x22,\\x22method\\x22:'
            '\\x22login\\x22,\\x22params\\x22:{\\x22login\\x22:'
            '\\x2245u1zDdkh78CLRmu6mCkmsFWGZw6qtjHQTP26BXKQgAvH1NgGRLmTWg1ykpJ2qEizxeeKKAbcgu6X6FFafczhZEH468AWhR'
            '\\x22,\\x22pass\\x22:\\x22x\\x22,\\x22agent\\x22:'
            '\\x22XMRig/6.15.3',
            '(Windows', 'NT', '10.0;', 'Win64;', 'x64)', 'libuv/1.42.0',
            'msvc/2019\\x22,\\x22algo\\x22:[\\x22cn/1\\x22,\\x22cn/2\\x22,'
            '\\x22cn/r\\x22,\\x22cn/fast\\x22,\\x22cn/half\\x22,'
            '\\x22cn/xao\\x22,\\x22cn/rto\\x22,\\x22cn/rwz\\x22,'
            '\\x22cn/zls\\x22,\\x22cn/double\\x22,\\x22cn/ccx\\x22,'
            '\\x22cn-lite/1\\x22,\\x22cn-heavy/0\\x22,\\x22cn-heavy/tube'
            '\\x22,\\x22cn-heavy/xhv\\x22,\\x22cn-pico\\x22,\\x22cn-pico/tlo'
            '\\x22,\\x22cn/upx2\\x22,\\x22rx/0\\x22,\\x22rx/wow\\x22,'
            '\\x22rx/arq\\x22,\\x22rx/graft\\x22,\\x22rx/sfx\\x22,'
            '\\x22rx/keva\\x22,\\x22argon2/chukwa\\x22,\\x22argon2/chukwav2'
            '\\x22,\\x22argon2/ninja\\x22,\\x22astrobwt\\x22]}}'
        ], 400, 157, '-', '-'], [
        '220918 013307', '    106.75.178.0', [
            '{\\x22params\\x22:', '[\\x22miner1\\x22,', '\\x22password\\x22],',
            '\\x22id\\x22:', '2,', '\\x22method\\x22:',
            '\\x22mining.authorize\\x22}'], 400, 157, '-', '-'], [
        '220918 013308', '    106.75.178.0', [
            '{\\x22id\\x22:1,\\x22jsonrpc\\x22:\\x222.0\\x22,\\x22method\\x22:'
            '\\x22login\\x22,\\x22params\\x22:{\\x22login\\x22:\\x22blue1'
            '\\x22,\\x22pass\\x22:\\x22x\\x22,\\x22agent\\x22:\\x22Windows',
            'NT', '6.1;', 'Win64;', 'x64\\x22}}'], 400, 157, '-', '-'], [
        '220918 013309', '    106.75.178.0', [
            '{\\x22params\\x22:', '[\\x22miner1\\x22,', '\\x22bf\\x22,',
            '\\x2200000001\\x22,', '\\x22504e86ed\\x22,',
            '\\x22b2957c02\\x22],', '\\x22id\\x22:', '4,',
            '\\x22method\\x22:', '\\x22mining.submit\\x22}'
        ], 400, 157, '-', '-']]


@patch('native_list.requests.get', spec=Response)
def test_remove_googlebot(mock_get, chrono_reqs):
    # This can be slow so we're only going to test the first 2000 requests.
    sample_size = 2000
    with open("sample_gbots.json") as f:
        SAMPLE_GBOTS = json.load(f)
    mock_get.return_value.json.return_value = SAMPLE_GBOTS
    req_list_fltrd = ChronoReqs.remove_googlebot(
        chrono_reqs.req_list[:sample_size])
    assert(len(req_list_fltrd)) == 1933


