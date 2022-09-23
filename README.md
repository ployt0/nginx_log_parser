# nginx_log_parser

Loving learning nginx, here's a parser to help analyse logs

## Usage

```shell
nginx_digester/main.py access.log
```

or:

```shell
docker logs nginx_cont | nginx_digester/main.py access.log
```

Still need to actually do something with the output.
