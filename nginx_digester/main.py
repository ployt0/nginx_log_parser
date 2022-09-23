#!/usr/bin/env python3
"""
Ingests nginx logs for querying/graphing.

Originally this would use ReqByIP to store them by IP. That's fine for DOS
protection but very inefficient for time series analysis which is why ChronoReqs
was created.

----

Quick and dirty shell command alternative/precursor:
docker logs nginx_cont | awk '{print $1}' | sort | uniq -c | sort -b -n

Cons:
    - `6 /docker-entrypoint.sh:` the logs contain debug/info lines that pollute.
    - Other fields are not so easy to obtain.
Pros:
    - Fast to see who makes most requests.

https://tools.keycdn.com/geo is good for geolocations. It has an API!!!
https://iplocation.io/ip/107.175.245.18 and https://www.iplocation.net/ip-lookup both aggregate several geoloc services.
"""

import argparse
import sys
import json

from reqs_by_ip import ReqByIP

KNOWN_FRIENDLY_TESTERS = {"172.18.0.1", "46.64.34.27"}



def main(arg_list: list):
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', nargs='?')
    args = parser.parse_args(arg_list)
    if args.filename:
        reqs = ReqByIP(open(args.filename).read(), KNOWN_FRIENDLY_TESTERS)
    elif not sys.stdin.isatty():
        reqs = ReqByIP(sys.stdin.read(), KNOWN_FRIENDLY_TESTERS)
    else:
        parser.print_help()


if __name__ == '__main__':
    main(sys.argv[1:])


