#!/usr/bin/env python3
import argparse
import os
from datetime import datetime

import dotenv
import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filename", required=True)
    parser.add_argument("--measurement", required=True)
    parser.add_argument("--fields", nargs="*")
    args = parser.parse_args()
    dotenv.load_dotenv()

    data = []
    with open(args.filename) as f:
        for line in f:
            split = line.strip().split("\t")
            time = datetime.strptime(split[0], "%Y-%m-%d %H:%M:%S.%f")
            assert len(split) == len(args.fields) + 1
            kvs = []
            for field, value in zip(args.fields, split[1:]):
                kvs.append(f"{field}={value}")
            values = ",".join(kvs)
            timestamp = int(time.timestamp())
            datum = f"{args.measurement} {values} {timestamp}"
            data.append(datum)
    data = "\n".join(data)

    dbhost = os.getenv("INFLUXDB_HOST")
    dbuser = os.getenv("INFLUXDB_USER")
    dbpass = os.getenv("INFLUXDB_PASS")
    dbname = os.getenv("INFLUXDB_NAME")
    url = f"{dbhost}/api/v2/write?bucket={dbname}&precision=s"
    session = requests.Session()
    session.headers["Authorization"] = f"Token {dbuser}:{dbpass}"
    r = session.post(url, data=data)
    try:
        r.raise_for_status()
    except:
        print(r.headers)
        print(r.json())
        raise
    print("Done")


if __name__ == "__main__":
    main()
