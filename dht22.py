#!/usr/bin/env python3
import os
import sys
import time
import signal
from typing import *  # pylint: disable=unused-wildcard-import

import Adafruit_DHT
import dotenv
import requests


class DHT22:
    def __init__(
        self,
        *,
        gpio_pin: int,
        interval: int,
        dbhost: str,
        dbuser: str,
        dbpass: str,
        dbname: str,
        dbtable: str,
    ):
        self._gpio_pin = gpio_pin
        self._interval = interval
        self._measurement = dbtable

        self._url = f"{dbhost}/api/v2/write?bucket={dbname}&precision=s"
        self._session = requests.Session()
        self._session.headers["Authorization"] = f"Token {dbuser}:{dbpass}"
    
    def _read(self) -> Tuple[float, float]:
        h, t = Adafruit_DHT.read_retry(Adafruit_DHT.DHT22, self._gpio_pin)
        return h, t

    def _report(self):
        h, t = self._read()
        data = f"{self._measurement} temperature={t},humidity={h}"
        r = self._session.post(self._url, data=data)
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\n")
            sys.stderr.flush()

    def Run(self):
        try:
            h, t = self._read()
            print(f'First read: temp={t:.1f}, humidity={h:.1f}\n')
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

    o = DHT22(
        gpio_pin=int(os.getenv("DHT22_GPIO_PIN")),
        interval=int(os.getenv("DHT22_INTERVAL")),
        dbhost=os.getenv("INFLUXDB_HOST"),
        dbuser=os.getenv("INFLUXDB_USER"),
        dbpass=os.getenv("INFLUXDB_PASS"),
        dbname=os.getenv("INFLUXDB_NAME"),
        dbtable=os.getenv("DHT22_INFLUXDB_MEASUREMENT"),
    )
    o.Run()


if __name__ == "__main__":
    main()
