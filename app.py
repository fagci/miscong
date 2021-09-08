#!/usr/bin/env python3

from argparse import ArgumentParser
from http.client import HTTPConnection
from ipaddress import IPV4LENGTH, IPv4Address
from pathlib import Path
from random import randrange
from threading import Event, Lock, Thread
from time import sleep

MAX_IPV4 = 1 << IPV4LENGTH

HEADERS = {'User-Agent': 'Mozilla/5.0'}


class Checker(HTTPConnection):
    __slots__ = ('fuzz_list', 'timeout')

    def __init__(self, fuzz_list, address, timeout, debuglevel=0):
        super().__init__('%s:%d' % address, timeout=timeout)
        self.fuzz_list = fuzz_list
        self.set_debuglevel(debuglevel)

    def run_checks(self):
        for path in self.fuzz_list:
            code, size, body = self.check(path)

            if code in {400, 401, 403} or code % 100 == 5:
                return

            if 100 <= code < 300:
                yield code, size, path, body

    def pre(self):
        self.request('GET', '/', headers=HEADERS)
        r = self.getresponse()
        r.read()
        server = r.getheader('Server')
        return server and 'nginx' in server

    def check(self, path):
        self.request('GET', path, headers=HEADERS)
        r = self.getresponse()
        data = r.read()
        return r.status, len(data), data

    def __enter__(self):
        return self

    def __exit__(self, _, eo, __):
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
                ip = next(self.gen)

            with Checker(self.fuzz_list, (ip, 80), self.timeout, self.debuglevel) as checker:
                if True or checker.pre():
                    for code, size, path, body in checker.run_checks():
                        with self.__print_lock:
                            # print(f'{ip:<15} {code:<3} {size:>9} {path}')
                            if b'<html>' not in body and b'DOCTYPE' not in body:
                                print('[+]', ip, path)
                                print('  >>>', body.decode(errors='ignore').splitlines()[0])

    def generate_ips(self, count):
        while count:
            ip_address = IPv4Address(randrange(0, MAX_IPV4))
            if ip_address.is_global and not ip_address.is_multicast:
                count -= 1
                yield str(ip_address)

    def scan(self, workers, timeout, limit):
        threads = []
        self.timeout = timeout
        self.gen = self.generate_ips(limit)

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


def main():
    ap = ArgumentParser()
    ap.add_argument('list', type=str)
    ap.add_argument('-w', '--workers', type=int, default=512)
    ap.add_argument('-t', '--timeout', type=float, default=3)
    ap.add_argument('-l', '--limit', type=int, default=1000000)
    ap.add_argument('-d', '--debuglevel', type=int, default=0)
    args = ap.parse_args()

    scanner = Scanner(args.list, args.debuglevel)
    scanner.scan(args.workers, args.timeout, args.limit)


if __name__ == '__main__':
    main()
