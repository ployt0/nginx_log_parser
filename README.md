# nginx_log_parser

![python-app workflow](https://github.com/ployt0/nginx_log_parser/actions/workflows/python-app.yml/badge.svg)

Exploring nginx; here's a parser to help analyse logs.

## Usage

```shell
nginx_digester/main.py access.log
```

or:

```shell
docker logs nginx_cont | nginx_digester/main.py access.log
```

I provided tests/access.log for testing. It was curated using the simplest of nginx configurations. I anonymised it as best I could because I can't prove 99% of the addresses were bots.

