#!/usr/bin/env python3
# Adapted from https://github.com/satcar77/miband4

import sys
import os
import struct
import time
import logging
from datetime import datetime, timedelta

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


class MiBandDelegate(DefaultDelegate):
    def __init__(self, device):
        super().__init__()
        self._log = logging.getLogger(self.__class__.__name__)
        self.device = device
        self.pkg = 0

    def handleNotification(self, hnd, data):
        self._log.debug(f'Notification. hnd: {hnd}. data: {data}')
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
                    "Fetch data from %d-%d-%d %d:%d", year, month, day, hour, minute
                )
                self.pkg = 0  # reset the packing index
                self.device._char_fetch.write(b"\x02", False)
            elif data[:3] == b"\x10\x02\x01":
                timestamp_diff = self.device.end_timestamp - self.device.last_timestamp
                if timedelta(minutes=1) > timestamp_diff:
                    self._log.info("Finished fetching")
                    return
                self._log.info("Trigger more communication")
                time.sleep(1)
                t = self.device.last_timestamp + timedelta(minutes=1)
                self.device.start_get_previews_data(t)

            elif data[:3] == b"\x10\x02\x04":
                self._log.info("No more activity fetch possible")
                return
            else:
                self._log.info(
                    "Unexpected data on handle " + str(hnd) + ": " + str(data)
                )
                return
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
                    if timestamp < self.device.end_timestamp:
                        self.device.activity_callback(
                            timestamp, category, intensity, steps, heart_rate
                        )
                    i += 4
            else:
                self._log.warning(f"len(data) % 4 != 1. len(data) = {len(data)}")
        else:
            self._log.warning(f"Unknown handle: {hnd}")


class MiBand(Peripheral):
    _send_rnd_cmd = struct.pack("<2s", b"\x02\x00")
    _send_enc_key = struct.pack("<2s", b"\x03\x00")

    def __init__(self, mac_address, key, timeout=0.5):
        self._log = logging.getLogger(self.__class__.__name__)
        self._log.info("Connecting to " + mac_address)
        super().__init__(mac_address, addrType=ADDR_TYPE_PUBLIC)
        self._log.info("Connected")
        if not key:
            self.setSecurityLevel(level="medium")
        self.timeout = timeout
        self.mac_address = mac_address
        self.state = None
        self.heart_measure_callback = None
        self.heart_raw_callback = None
        self.accel_raw_callback = None
        self.auth_key = key
        self.svc_1 = self.getServiceByUUID(UUIDS.SERVICE_MIBAND1)
        self.svc_2 = self.getServiceByUUID(UUIDS.SERVICE_MIBAND2)

        self._char_auth = self.svc_2.getCharacteristics(UUIDS.CHARACTERISTIC_AUTH)[0]
        self._desc_auth = self._char_auth.getDescriptors(
            forUUID=UUIDS.NOTIFICATION_DESCRIPTOR
        )[0]

        # Recorded information
        self._char_fetch = self.getCharacteristics(uuid=UUIDS.CHARACTERISTIC_FETCH)[0]
        self._desc_fetch = self._char_fetch.getDescriptors(
            forUUID=UUIDS.NOTIFICATION_DESCRIPTOR
        )[0]
        self._char_activity = self.getCharacteristics(
            uuid=UUIDS.CHARACTERISTIC_ACTIVITY_DATA
        )[0]
        self._desc_activity = self._char_activity.getDescriptors(
            forUUID=UUIDS.NOTIFICATION_DESCRIPTOR
        )[0]

        self._auth_notif(True)
        self.activity_notif_enabled = False
        self.waitForNotifications(0.1)
        self.setDelegate(MiBandDelegate(self))

    def _auth_notif(self, enabled):
        if enabled:
            self._log.info("Enabling Auth Service notifications status...")
            self._desc_auth.write(b"\x01\x00", True)
        elif not enabled:
            self._log.info("Disabling Auth Service notifications status...")
            self._desc_auth.write(b"\x00\x00", True)
        else:
            self._log.error(
                "Something went wrong while changing the Auth Service notifications status..."
            )

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
        self._char_auth.write(self._send_rnd_cmd)
        self.waitForNotifications(self.timeout)

    def _send_enc_rdn(self, data):
        self._log.info("Sending encrypted random number")
        cmd = self._send_enc_key + self._encrypt(data)
        send_cmd = struct.pack("<18s", cmd)
        self._char_auth.write(send_cmd)
        self.waitForNotifications(self.timeout)

    def _encrypt(self, message):
        aes = AES.new(self.auth_key, AES.MODE_ECB)
        return aes.encrypt(message)

    def send_custom_alert(self, type, phone):
        if type == 5:
            base_value = "\x05\x01"
        elif type == 4:
            base_value = "\x04\x01"
        elif type == 3:
            base_value = "\x03\x01"
        svc = self.getServiceByUUID(UUIDS.SERVICE_ALERT_NOTIFICATION)
        char = svc.getCharacteristics(UUIDS.CHARACTERISTIC_CUSTOM_ALERT)[0]
        char.write(bytes(base_value + phone, "utf-8"), withResponse=True)

    def get_steps(self):
        char = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_STEPS)[0]
        a = char.read()
        steps = struct.unpack("h", a[1:3])[0] if len(a) >= 3 else None
        meters = struct.unpack("h", a[5:7])[0] if len(a) >= 7 else None
        fat_burned = struct.unpack("h", a[2:4])[0] if len(a) >= 4 else None
        # why only 1 byte??
        calories = struct.unpack("b", a[9:10])[0] if len(a) >= 10 else None
        return {
            "steps": steps,
            "meters": meters,
            "fat_burned": fat_burned,
            "calories": calories,
        }

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

    def get_battery_info(self):
        char = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_BATTERY)[0]
        return self._parse_battery_response(char.read())

    def get_current_time(self):
        char = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_CURRENT_TIME)[0]
        return self._parse_date(char.read()[0:9])

    def set_current_time(self, date):
        char = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_CURRENT_TIME)[0]
        return char.write(self.create_date_data(date), True)

    def start_get_previews_data(self, start_timestamp):
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
        self.active = True

    def get_activity_betwn_intervals(self, start_timestamp, end_timestamp, callback):
        self.end_timestamp = end_timestamp
        self.start_get_previews_data(start_timestamp)
        self.activity_callback = callback


def activity_log_callback(timestamp, c, i, s, h):
    print(
        "{}: category: {}; intensity {}; steps {}; heart rate {};".format(
            timestamp.strftime("%Y-%m-%d %H:%M:%S"), c, i, s, h
        )
    )


def main():
    logging.basicConfig(level=logging.DEBUG)

    mac_addr = "e6:26:7c:a8:f5:a1"
    auth_key = bytes.fromhex("6ba1b8cb20edb2a2ba8498f85a954198")

    ok = False
    while not ok:
        try:
            band = MiBand(mac_addr, auth_key)
            ok = band.initialize()
        except BTLEDisconnectError:
            print("Connection to the MIBand failed. Trying out again in 3 seconds")
            time.sleep(3)
        except KeyboardInterrupt:
            print("\nExit.")
            exit()

    temp = datetime.now()
    band.get_activity_betwn_intervals(
        datetime(temp.year, temp.month, temp.day), datetime.now(), activity_log_callback
    )
    while True:
        band.waitForNotifications(0.2)


if __name__ == "__main__":
    main()
