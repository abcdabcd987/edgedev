#!/usr/bin/env python3
import os
import sys
import time
import signal
from typing import *  # pylint: disable=unused-wildcard-import

import dotenv
import requests
import serial


class MH_Z19B:
    def __init__(
        self,
        *,
        serial_port: str,
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

        self._serial = serial.Serial(serial_port, 9600, timeout=2.0)

    @staticmethod
    def CRC8(b: bytes) -> int:
        crc = sum(b[1:8])
        crc %= 256
        crc = ~crc & 0xFF
        crc += 1
        return crc

    def _read_co2(self) -> int:
        # Code adapted from: https://www.circuits.dk/testing-mh-z19-ndir-co2-sensor-module/
        self._serial.write(b"\xff\x01\x86\x00\x00\x00\x00\x00\x79")
        time.sleep(0.1)
        b = self._serial.read(9)
        crc = MH_Z19B.CRC8(b)
        if crc != b[8]:
            raise ValueError(f"CRC error. Calculated: {crc} Bytes: {b.hex()}")
        co2 = b[2] * 256 + b[3]
        return co2

    def _report(self):
        co2 = self._read_co2()
        data = f"{self._measurement} co2={co2}"
        r = self._session.post(self._url, data=data)
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\n")
            sys.stderr.flush()

    def Run(self):
        try:
            co2 = self._read_co2()
            print(f'First read: co2={co2}ppm')
            time.sleep(self._interval)

            while True:
                self._report()
                time.sleep(self._interval)
        except KeyboardInterrupt:
            sys.stderr.write("Exiting...\n")
        sys.stderr.flush()


def main():
    signal.signal(signal.SIGINT, signal.default_int_handler)
    dotenv.load_dotenv()

    o = MH_Z19B(
        serial_port=os.getenv("MH_Z19B_SERIAL_PORT"),
        interval=int(os.getenv("MH_Z19B_INTERVAL")),
        dbhost=os.getenv("INFLUXDB_HOST"),
        dbuser=os.getenv("INFLUXDB_USER"),
        dbpass=os.getenv("INFLUXDB_PASS"),
        dbname=os.getenv("INFLUXDB_NAME"),
        dbtable=os.getenv("MH_Z19B_INFLUXDB_MEASUREMENT"),
    )
    o.Run()


if __name__ == "__main__":
    main()
