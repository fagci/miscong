#!/usr/bin/env python3

from argparse import ArgumentParser
from http.client import HTTPConnection
from ipaddress import IPV4LENGTH, IPv4Address, IPv4Network
from pathlib import Path
from random import randrange
from threading import Event, Lock, Thread
from time import sleep

MAX_IPV4 = 1 << IPV4LENGTH

HEADERS = {'User-Agent': 'Mozilla/5.0'}

STATS = Path(__file__).resolve().parent / 'stats.txt'

class Checker(HTTPConnection):
    __slots__ = ('fuzz_list', 'timeout')

    def __init__(self, fuzz_list, address, timeout, debuglevel=0):
        super().__init__('%s:%d' % address, timeout=timeout)
        self.fuzz_list = fuzz_list
        self.set_debuglevel(debuglevel)

    def run_checks(self):
        for path in self.fuzz_list:
            code, size, body = self.check(path)

            # if code in {400, 401, 403} or code % 100 == 5:
            #     return

            if code in {200,204} and body:
                body_str = body.decode(errors='ignore')
                body_lower = body_str.lower()
                if all(k not in body_lower for k in {'<body','<html','<head','<title', '<!doctype','<h1', '<b>', '<p>','<br>'}):
                    yield code, size, path, body_str

    def pre(self):
        rnd = ''.join(chr(randrange(ord('a'), ord('z')+1))
                              for _ in range(8))
        self.request('GET', f'/{rnd}', headers=HEADERS)
        r = self.getresponse()
        r.read()
        if 200 <= r.status < 300:
            return False # SPA
        return True

    def check(self, path):
        self.request('GET', path, headers=HEADERS)
        r = self.getresponse()
        data = r.read()
        return r.status, len(data), data

    def __enter__(self):
        return self

    def __exit__(self, _, eo, __):
        try:
            self.close()
        except:
            pass
        return not isinstance(eo, KeyboardInterrupt)


class Scanner:
    __print_lock = Lock()
    __gen_lock = Lock()
    __run_event = Event()

    def __init__(self, list_file_path, debuglevel):
        list_path = Path(list_file_path).resolve()
        self.debuglevel = debuglevel

        with list_path.open() as lst:
            lines = map(str.strip, lst.readlines())
            self.fuzz_list = list(
                filter(lambda ln: ln and not ln.startswith('#'), lines))

    def __check(self):
        while self.__run_event.is_set():

            with self.__gen_lock:
                try:
                    host = next(self.gen)
                except StopIteration:
                    self.__run_event.clear()
                    return

            with Checker(self.fuzz_list, (host, 80), self.timeout, self.debuglevel) as checker:
                if checker.pre():
                    for code, size, path, body in checker.run_checks():
                        with self.__print_lock:
                            print(f'{host:<15} {code:<3} {size:>9} {path}')
                            print('  >>>', body.splitlines()[0])
                            with STATS.open('a') as sf:
                                sf.write(f'{host} {path}\n')

    def generate_ips(self, count, net, host):
        if host:
            yield host
            return
        if net:
            for host in IPv4Network(net, strict=False).hosts():
                yield str(host)
            return
        while count:
            ip_address = IPv4Address(randrange(0, MAX_IPV4))
            if ip_address.is_global and not ip_address.is_multicast:
                count -= 1
                yield str(ip_address)

    def scan(self, workers, timeout, limit, net, host):
        threads = []
        self.timeout = timeout
        self.gen = self.generate_ips(limit, net, host)

        for _ in range(workers):
            t = Thread(target=self.__check, daemon=True)
            threads.append(t)

        self.__run_event.set()

        for t in threads:
            t.start()

        try:
            while all(t.is_alive() for t in threads):
                sleep(0.25)
        except KeyboardInterrupt:
            self.__run_event.clear()
            print('Interrupted')
        for t in threads:
            t.join()


def main():
    ap = ArgumentParser()
    ap.add_argument('list', type=str)
    ap.add_argument('-w', '--workers', type=int, default=512)
    ap.add_argument('-t', '--timeout', type=float, default=3)
    ap.add_argument('-l', '--limit', type=int, default=1000000)
    ap.add_argument('-d', '--debuglevel', type=int, default=0)
    ap.add_argument('-n', '--net', type=str, default='')
    ap.add_argument('--host', type=str, default='')
    args = ap.parse_args()

    scanner = Scanner(args.list, args.debuglevel)
    scanner.scan(args.workers, args.timeout, args.limit, args.net, args.host)


if __name__ == '__main__':
    main()
