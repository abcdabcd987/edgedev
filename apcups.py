#!/usr/bin/env python3
import os
import sys
import time
import signal
import socket
from typing import *  # pylint: disable=unused-wildcard-import

import dotenv
import requests
import serial


class ApcUps:
    def __init__(
        self,
        *,
        nis_host: str,
        nis_port: int,
        interval: int,
        dbhost: str,
        dbuser: str,
        dbpass: str,
        dbname: str,
        dbtable: str,
    ):
        self._interval = interval
        self._measurement = dbtable

        self._url = f"{dbhost}/api/v2/write?bucket={dbname}&precision=s"
        self._session = requests.Session()
        self._session.headers["Authorization"] = f"Token {dbuser}:{dbpass}"

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((nis_host, nis_port))

    def _read(self) -> dict:
        # http://www.apcupsd.com/manual/manual.html#nis-network-server-protocol
        self._socket.sendall(b"\x00\x06status")
        d = {}
        while True:
            buf = self._socket.recv(2)
            assert len(buf) == 2
            msg_len = buf[0] * 256 + buf[1]
            if msg_len == 0:
                break
            msg = self._socket.recv(msg_len)
            assert len(msg) == msg_len
            k, v = map(str.strip, str(msg, encoding="utf-8").split(":", maxsplit=1))
            d[k] = v
        return d

    def _report(self):
        d = self._read()
        keys = ["LINEV", "LOADPCT", "BCHARGE", "BATTV"]
        kv = {k: float(d[k].split()[0]) for k in keys}
        kv["w"] = kv["LOADPCT"] * float(d["NOMPOWER"].split()[0]) / 100
        values = ",".join(f"{k}={v}" for k, v in kv.items())
        data = f"{self._measurement} {values}"
        r = self._session.post(self._url, data=data)
        r.raise_for_status()

    def Run(self):
        try:
            while True:
                self._report()
                time.sleep(self._interval)
        except KeyboardInterrupt:
            sys.stderr.write("Exiting...\n")
        sys.stderr.flush()


def main():
    signal.signal(signal.SIGINT, signal.default_int_handler)
    dotenv.load_dotenv()

    o = ApcUps(
        nis_host=os.getenv("APCUPS_HOST"),
        nis_port=int(os.getenv("APCUPS_PORT")),
        interval=int(os.getenv("APCUPS_INTERVAL")),
        dbhost=os.getenv("INFLUXDB_HOST"),
        dbuser=os.getenv("INFLUXDB_USER"),
        dbpass=os.getenv("INFLUXDB_PASS"),
        dbname=os.getenv("INFLUXDB_NAME"),
        dbtable=os.getenv("APCUPS_INFLUXDB_MEASUREMENT"),
    )
    o.Run()


if __name__ == "__main__":
    main()
