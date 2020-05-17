#!/usr/bin/env python3
# Adapted from https://github.com/satcar77/miband4

import dataclasses
import logging
import os
import signal
import sys
import struct
import time
from datetime import datetime, timedelta
from typing import *  # pylint: disable=unused-wildcard-import

import dotenv
import requests
from bluepy.btle import (
    Peripheral,
    DefaultDelegate,
    ADDR_TYPE_PUBLIC,
    BTLEDisconnectError,
)
from Crypto.Cipher import AES


class UUIDS:
    BASE = "0000%s-0000-1000-8000-00805f9b34fb"

    SERVICE_MIBAND1 = BASE % "fee0"
    SERVICE_MIBAND2 = BASE % "fee1"

    SERVICE_ALERT = BASE % "1802"
    SERVICE_ALERT_NOTIFICATION = BASE % "1811"
    SERVICE_HEART_RATE = BASE % "180d"
    SERVICE_DEVICE_INFO = BASE % "180a"

    CHARACTERISTIC_HZ = "00000002-0000-3512-2118-0009af100700"
    CHARACTERISTIC_SENSOR = "00000001-0000-3512-2118-0009af100700"
    CHARACTERISTIC_AUTH = "00000009-0000-3512-2118-0009af100700"
    CHARACTERISTIC_HEART_RATE_MEASURE = "00002a37-0000-1000-8000-00805f9b34fb"
    CHARACTERISTIC_HEART_RATE_CONTROL = "00002a39-0000-1000-8000-00805f9b34fb"
    CHARACTERISTIC_ALERT = "00002a06-0000-1000-8000-00805f9b34fb"
    CHARACTERISTIC_CUSTOM_ALERT = "00002a46-0000-1000-8000-00805f9b34fb"
    CHARACTERISTIC_BATTERY = "00000006-0000-3512-2118-0009af100700"
    CHARACTERISTIC_STEPS = "00000007-0000-3512-2118-0009af100700"
    CHARACTERISTIC_LE_PARAMS = BASE % "FF09"
    CHARACTERISTIC_REVISION = 0x2A28
    CHARACTERISTIC_SERIAL = 0x2A25
    CHARACTERISTIC_HRDW_REVISION = 0x2A27
    CHARACTERISTIC_CONFIGURATION = "00000003-0000-3512-2118-0009af100700"
    CHARACTERISTIC_DEVICEEVENT = "00000010-0000-3512-2118-0009af100700"
    CHARACTERISTIC_CHUNKED_TRANSFER = "00000020-0000-3512-2118-0009af100700"
    CHARACTERISTIC_MUSIC_NOTIFICATION = "00000010-0000-3512-2118-0009af100700"
    CHARACTERISTIC_CURRENT_TIME = BASE % "2A2B"
    CHARACTERISTIC_AGE = BASE % "2A80"
    CHARACTERISTIC_USER_SETTINGS = "00000008-0000-3512-2118-0009af100700"
    CHARACTERISTIC_ACTIVITY_DATA = "00000005-0000-3512-2118-0009af100700"
    CHARACTERISTIC_FETCH = "00000004-0000-3512-2118-0009af100700"

    NOTIFICATION_DESCRIPTOR = 0x2902

    # Device Firmware Update
    SERVICE_DFU_FIRMWARE = "00001530-0000-3512-2118-0009af100700"
    CHARACTERISTIC_DFU_FIRMWARE = "00001531-0000-3512-2118-0009af100700"
    CHARACTERISTIC_DFU_FIRMWARE_WRITE = "00001532-0000-3512-2118-0009af100700"


class AUTH_STATES:
    AUTH_OK = "Auth ok"
    AUTH_FAILED = "Auth failed"
    ENCRIPTION_KEY_FAILED = "Encryption key auth fail, sending new key"
    KEY_SENDING_FAILED = "Key sending failed"
    REQUEST_RN_ERROR = "Something went wrong when requesting the random number"


@dataclasses.dataclass
class ActivityEntry:
    time: datetime
    category: int
    intensity: int
    steps: int
    heart_rate: Optional[int]


class MiBandDelegate(DefaultDelegate):
    def __init__(self, device):
        super().__init__()
        self._log = logging.getLogger(self.__class__.__name__)
        self.device = device
        self.pkg = 0

    def handleNotification(self, hnd, data):
        self._log.debug(f"Notification. hnd: {hnd}. data: {data}")
        if hnd == self.device._char_auth.getHandle():
            if data[:3] == b"\x10\x01\x01":
                self.device._req_rdn()
            elif data[:3] == b"\x10\x01\x04":
                self.device.state = AUTH_STATES.KEY_SENDING_FAILED
            elif data[:3] == b"\x10\x02\x01":
                # 16 bytes
                random_nr = data[3:]
                self.device._send_enc_rdn(random_nr)
            elif data[:3] == b"\x10\x02\x04":
                self.device.state = AUTH_STATES.REQUEST_RN_ERROR
            elif data[:3] == b"\x10\x03\x01":
                self.device.state = AUTH_STATES.AUTH_OK
            elif data[:3] == b"\x10\x03\x04":
                self.device.state = AUTH_STATES.ENCRIPTION_KEY_FAILED
            else:
                self.device.state = AUTH_STATES.AUTH_FAILED
        # The fetch characteristic controls the communication with the activity characteristic.
        elif hnd == self.device._char_fetch.getHandle():
            if data[:3] == b"\x10\x01\x01":
                # get timestamp from what date the data actually is received
                year = struct.unpack("<H", data[7:9])[0]
                month = struct.unpack("b", data[9:10])[0]
                day = struct.unpack("b", data[10:11])[0]
                hour = struct.unpack("b", data[11:12])[0]
                minute = struct.unpack("b", data[12:13])[0]
                self.device.first_timestamp = datetime(year, month, day, hour, minute)
                self._log.info(
                    "Receiving data from %d-%02d-%02d %02d:%02d",
                    year,
                    month,
                    day,
                    hour,
                    minute,
                )
                self.pkg = 0  # reset the packing index
                self.device._char_fetch.write(b"\x02", False)
            elif data[:3] == b"\x10\x02\x01":
                self._log.info("Finished fetching")
                self.device.activity_ctx.ready = True
            elif data[:3] == b"\x10\x02\x04":
                self._log.info("No more activity to fetch")
                self.device.activity_ctx.ready = True
            else:
                self._log.info(f"Unexpected data on handle {hnd}: {data}")
        elif hnd == self.device._char_activity.getHandle():
            if len(data) % 4 == 1:
                self.pkg += 1
                i = 1
                while i < len(data):
                    index = int(self.pkg) * 4 + (i - 1) / 4
                    timestamp = self.device.first_timestamp + timedelta(minutes=index)
                    self.device.last_timestamp = timestamp
                    category = struct.unpack("<B", data[i : i + 1])[0]
                    intensity = struct.unpack("B", data[i + 1 : i + 2])[0]
                    steps = struct.unpack("B", data[i + 2 : i + 3])[0]
                    heart_rate = struct.unpack("B", data[i + 3 : i + 4])[0]
                    entry = ActivityEntry(
                        timestamp,
                        category,
                        intensity,
                        steps,
                        None if heart_rate == 255 else heart_rate,
                    )
                    self.device.activity_ctx.activities.append(entry)
                    i += 4
            else:
                self._log.warning(f"len(data) % 4 != 1. len(data) = {len(data)}")
        else:
            self._log.warning(f"Unknown handle: {hnd}")


class MiBand4Device(Peripheral):
    @dataclasses.dataclass
    class ActivityContext:
        ready: bool
        activities: List[ActivityEntry]

    def __init__(self, mac_address, key):
        self._log = logging.getLogger(self.__class__.__name__)
        self._log.info("Connecting to " + mac_address)
        super().__init__(mac_address, addrType=ADDR_TYPE_PUBLIC)
        self._log.info("Connected")
        self.mac_address = mac_address
        self.state = None
        self.auth_key = key

        # fmt: off
        self.svc_1 = self.getServiceByUUID(UUIDS.SERVICE_MIBAND1)
        self.svc_2 = self.getServiceByUUID(UUIDS.SERVICE_MIBAND2)
        self._char_auth = self.svc_2.getCharacteristics(UUIDS.CHARACTERISTIC_AUTH)[0]
        self._desc_auth = self._char_auth.getDescriptors(UUIDS.NOTIFICATION_DESCRIPTOR)[0]
        self._char_fetch = self.getCharacteristics(uuid=UUIDS.CHARACTERISTIC_FETCH)[0]
        self._desc_fetch = self._char_fetch.getDescriptors(UUIDS.NOTIFICATION_DESCRIPTOR)[0]
        self._char_activity = self.getCharacteristics(uuid=UUIDS.CHARACTERISTIC_ACTIVITY_DATA)[0]
        self._desc_activity = self._char_activity.getDescriptors(UUIDS.NOTIFICATION_DESCRIPTOR)[0]
        # fmt: on

        self._auth_notif(True)
        self.activity_notif_enabled = False
        self.waitForNotifications(0.1)
        self.withDelegate(MiBandDelegate(self))
        self.activity_ctx = self.ActivityContext(False, [])

    def _auth_notif(self, enabled: bool):
        if enabled:
            self._log.info("Enabling Auth Service notifications status...")
            self._desc_auth.write(b"\x01\x00", True)
        else:
            self._log.info("Disabling Auth Service notifications status...")
            self._desc_auth.write(b"\x00\x00", True)

    def _auth_previews_data_notif(self, enabled):
        if enabled:
            self._log.info("Enabling Fetch Char notifications status...")
            self._desc_fetch.write(b"\x01\x00", True)
            self._log.info("Enabling Activity Char notifications status...")
            self._desc_activity.write(b"\x01\x00", True)
            self.activity_notif_enabled = True
        else:
            self._log.info("Disabling Fetch Char notifications status...")
            self._desc_fetch.write(b"\x00\x00", True)
            self._log.info("Disabling Activity Char notifications status...")
            self._desc_activity.write(b"\x00\x00", True)
            self.activity_notif_enabled = False

    def initialize(self):
        self._log.info("Initializing")
        self._req_rdn()

        while True:
            self.waitForNotifications(0.1)
            if self.state == AUTH_STATES.AUTH_OK:
                self._log.info("Initialized")
                self._auth_notif(False)
                return True
            elif self.state is None:
                continue

            self._log.error(self.state)
            return False

    def _req_rdn(self):
        self._log.info("Requesting random number...")
        send_rnd_cmd = struct.pack("<2s", b"\x02\x00")
        self._char_auth.write(send_rnd_cmd)
        self.waitForNotifications(0.1)

    def _send_enc_rdn(self, data):
        self._log.info("Sending encrypted random number")
        send_enc_key = struct.pack("<2s", b"\x03\x00")
        cmd = send_enc_key + self._encrypt(data)
        send_cmd = struct.pack("<18s", cmd)
        self._char_auth.write(send_cmd)
        self.waitForNotifications(0.1)

    def _encrypt(self, message):
        aes = AES.new(self.auth_key, AES.MODE_ECB)
        return aes.encrypt(message)

    @staticmethod
    def _parse_date(bytes):
        year = struct.unpack("h", bytes[0:2])[0] if len(bytes) >= 2 else None
        month = struct.unpack("b", bytes[2:3])[0] if len(bytes) >= 3 else None
        day = struct.unpack("b", bytes[3:4])[0] if len(bytes) >= 4 else None
        hours = struct.unpack("b", bytes[4:5])[0] if len(bytes) >= 5 else None
        minutes = struct.unpack("b", bytes[5:6])[0] if len(bytes) >= 6 else None
        seconds = struct.unpack("b", bytes[6:7])[0] if len(bytes) >= 7 else None
        day_of_week = struct.unpack("b", bytes[7:8])[0] if len(bytes) >= 8 else None
        fractions256 = struct.unpack("b", bytes[8:9])[0] if len(bytes) >= 9 else None

        return {
            "date": datetime(*(year, month, day, hours, minutes, seconds)),
            "day_of_week": day_of_week,
            "fractions256": fractions256,
        }

    @staticmethod
    def create_date_data(date):
        data = struct.pack(
            "hbbbbbbbxx",
            date.year,
            date.month,
            date.day,
            date.hour,
            date.minute,
            date.second,
            date.weekday(),
            0,
        )
        return data

    def _parse_battery_response(self, bytes):
        level = struct.unpack("b", bytes[1:2])[0] if len(bytes) >= 2 else None
        last_level = struct.unpack("b", bytes[19:20])[0] if len(bytes) >= 20 else None
        status = "normal" if struct.unpack("b", bytes[2:3])[0] == b"0" else "charging"
        datetime_last_charge = self._parse_date(bytes[11:18])
        datetime_last_off = self._parse_date(bytes[3:10])

        res = {
            "status": status,
            "level": level,
            "last_level": last_level,
            "last_charge": datetime_last_charge,
            "last_off": datetime_last_off,
        }
        return res

    def GetBattery(self) -> int:
        char = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_BATTERY)[0]
        return self._parse_battery_response(char.read())["level"]

    def GetCurrentTime(self) -> datetime:
        char = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_CURRENT_TIME)[0]
        return self._parse_date(char.read()[0:9])["date"]

    def SetCurrentTime(self, date):
        char = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_CURRENT_TIME)[0]
        return char.write(self.create_date_data(date), True)

    def _start_get_activities(self, start_timestamp: datetime):
        if not self.activity_notif_enabled:
            self._auth_previews_data_notif(True)
            self.waitForNotifications(0.1)
        self._log.info("Trigger activity communication")
        year = struct.pack("<H", start_timestamp.year)
        month = struct.pack("b", start_timestamp.month)
        day = struct.pack("b", start_timestamp.day)
        hour = struct.pack("b", start_timestamp.hour)
        minute = struct.pack("b", start_timestamp.minute)
        ts = year + month + day + hour + minute
        trigger = b"\x01\x01" + ts + b"\x00\x17"
        self._char_fetch.write(trigger, False)

    def _get_activities_batch(self, start_timestamp: datetime):
        self.activity_ctx.ready = False
        self.activity_ctx.activities.clear()
        self._start_get_activities(start_timestamp)
        st = datetime.now()
        while not self.activity_ctx.ready:
            self.waitForNotifications(0.1)
            if datetime.now() - st > timedelta(seconds=30):
                self._log.warning("GetActivities timed out")
                break

    def GetActivities(self, start_timestamp: datetime) -> List[ActivityEntry]:
        now = datetime.now()
        start = start_timestamp
        activities: List[ActivityEntry] = []

        while now - start > timedelta(minutes=5):
            self._log.info(f"Requesting data from {start:%Y-%m-%d %H:%M}")
            try:
                self._get_activities_batch(start)
            except BTLEDisconnectError:
                self._log("Device disconnected unexpectly")
                break

            xs = self.activity_ctx.activities
            xs.sort(key=lambda x: x.time)
            cnt_stale = next(
                filter(lambda i: xs[i].time >= start, range(len(xs))), len(xs)
            )
            activities += xs[cnt_stale:]
            self._log.info(
                "Got new %d activity logs and %d stales ones.",
                len(xs) - cnt_stale,
                cnt_stale,
            )
            if len(xs) == cnt_stale:
                start = activities[-1].time + timedelta(days=1)
            else:
                start = activities[-1].time + timedelta(minutes=1)
        self._log.info(f"Got {len(activities)} activity logs in total.")
        return activities


class MiBand4:
    def __init__(
        self,
        *,
        mac_addr: str,
        auth_key: str,
        success_interval: int,
        failure_interval: int,
        dbhost: str,
        dbuser: str,
        dbpass: str,
        dbname: str,
        dbtable_activity: str,
        dbtable_device: str,
    ):
        self._log = logging.getLogger(self.__class__.__name__)
        if len(mac_addr) != 17:
            self._log.critical(
                "Incorrect format of MAC address (%s). Example: %s",
                mac_addr,
                "a1:c2:3d:4e:f5:6a",
            )
            exit(1)
        if len(auth_key) != 32:
            self._log.critical(
                "Incorrect format of AUTH_KEY (%s). Example: %s",
                auth_key,
                "8fa9b42078627a654d22beff985655db",
            )
            exit(1)
        self._mac_addr = mac_addr
        self._auth_key = bytes.fromhex(auth_key)
        self._success_interval = success_interval
        self._failure_interval = failure_interval
        self._dbtable_activity = dbtable_activity
        self._dbtable_device = dbtable_device

        self._url = f"{dbhost}/api/v2/write?bucket={dbname}&precision=s"
        self._session = requests.Session()
        self._session.headers["Authorization"] = f"Token {dbuser}:{dbpass}"

        url = f"{dbhost}/query?db={dbname}&epoch=s"
        query = f"SELECT * FROM {dbtable_activity} ORDER BY time DESC LIMIT 1"
        ret = self._session.get(url, params=dict(q=query)).json()
        try:
            timestamp = ret["results"][0]["series"][0]["values"][0][0]
            self._last_time = datetime.fromtimestamp(timestamp)
        except KeyError:
            self._last_time = datetime(2020, 1, 1)
        self._log.info(f"Setting last_time to {self._last_time:%Y-%m-%d %H:%M:%S}")

    def _collect(self) -> str:
        ok = False
        while not ok:
            band = MiBand4Device(self._mac_addr, self._auth_key)
            ok = band.initialize()

        activities = band.GetActivities(self._last_time)
        battery = band.GetBattery()
        now = datetime.now()
        current_time = band.GetCurrentTime()
        drift = (current_time - now).total_seconds()
        band.disconnect()
        self._log.info("Bluetooth disconnected.")

        if activities:
            self._last_time = activities[-1].time

        data = []
        for entry in activities:
            line = f"{self._dbtable_activity} category={entry.category},intensity={entry.intensity},steps={entry.steps}"
            if entry.heart_rate is not None:
                line += f",heart_rate={entry.heart_rate}"
            line += f" {int(entry.time.timestamp())}"
            data.append(line)
        line = f"{self._dbtable_device} battery={battery},clock_drift={drift} {int(now.timestamp())}"
        data.append(line)
        return "\n".join(data)

    def _report(self) -> bool:
        try:
            data = self._collect()
        except BTLEDisconnectError:
            self._log.info(f"Cannot talk to the device.")
            return False

        r = self._session.post(self._url, data=data)
        try:
            r.raise_for_status()
            self._log.info(f"Succeeded.")
            return True
        except requests.exceptions.HTTPError as e:
            self._log.error(e)
            return False

    def Run(self):
        try:
            while True:
                ok = self._report()
                sleep = self._success_interval if ok else self._failure_interval
                self._log.info(f"Sleep for {sleep} seconds")
                time.sleep(sleep)
        except KeyboardInterrupt:
            self._log.info("Exiting...")


def main():
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(filename)s:%(lineno)-4d] %(message)s",
        datefmt="%Y-%m-%d %H:%M%S",
        level=logging.INFO,
    )

    signal.signal(signal.SIGINT, signal.default_int_handler)
    dotenv.load_dotenv()

    o = MiBand4(
        mac_addr=os.getenv("MIBAND4_MAC_ADDR"),
        auth_key=os.getenv("MIBAND4_AUTH_KEY"),
        success_interval=int(os.getenv("MIBAND4_SUCCESS_INTERVAL")),
        failure_interval=int(os.getenv("MIBAND4_FAILURE_INTERVAL")),
        dbtable_activity=os.getenv("MIBAND4_INFLUXDB_MEASUREMENT_ACTIVITY"),
        dbtable_device=os.getenv("MIBAND4_INFLUXDB_MEASUREMENT_DEVICE"),
        dbhost=os.getenv("INFLUXDB_HOST"),
        dbuser=os.getenv("INFLUXDB_USER"),
        dbpass=os.getenv("INFLUXDB_PASS"),
        dbname=os.getenv("INFLUXDB_NAME"),
    )
    o.Run()


if __name__ == "__main__":
    main()
