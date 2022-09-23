import pytest

from line_parser import LogLineParser


@pytest.mark.parametrize("bit_after_time, expected_list", [
    ('"GET / HTTP/1.1" 404 153 "-" "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)" "-"',
     [["GET", "/", "HTTP/1.1"], 404, 153, "-", "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", "-"]),
    (r'"YOYO\x22 DA RUAN\x22 YANKA" 400 157 "-" "-" "-"',
     [[r"YOYO\x22", "DA", r"RUAN\x22", "YANKA"], 400, 157, "-", "-", "-"]),
    ('"" 400 0 "-" "-"',
     [[], 400, 0, "-", "-"])
])
def test_append_rest_of_line(bit_after_time, expected_list):
    list_target = []
    LogLineParser.append_rest_of_line(list_target, bit_after_time, 1)
    assert list_target == expected_list


@pytest.mark.parametrize("ip_dt_str, expect_ip, expect_dt_str", [
    ("44.44.44.44 - - [19/Sep/2022:08:01:21 +0000] ",
     "44.44.44.44", "220919 080121"),
    ("144.144.4.4 - - [01/Feb/2015:00:00:00 +0000] ",
     "144.144.4.4", "150201 000000"),
    ("144.144.4.4 - - [01/Feb/2015:00:00:00 +0500] ",
     "144.144.4.4", "150131 190000")
])
def test_find_ip_and_timestamp(ip_dt_str, expect_ip, expect_dt_str):
    ip, dt_str, curs = LogLineParser.find_ip_and_timestamp(ip_dt_str)
    assert curs == len(ip_dt_str) + 1
    assert ip == expect_ip
    assert dt_str == expect_dt_str
