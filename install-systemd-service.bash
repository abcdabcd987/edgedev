if [ "$#" -ne 2 ]; then
    echo "Usage: ./install-systemd-service.bash <executable> <service name>"
    exit 1
fi

exec_path="$(realpath $1)"
if [ ! -f "$exec_path" ]; then
    echo "$exec_path does not exist"
    exit 2
fi

service_name="$2.service"
service_path="/lib/systemd/system/$service_name"
if [ -f "$service_path" ]; then
    echo "Service $service_path already exists"
    exit 3
fi

cat > "$service_path" <<EOM
[Unit]
Description=Edgedev $1
After=network-online.target systemd-timesyncd.service
Requires=network-online.target

[Service]
Type=simple
ExecStart=$exec_path
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOM
if [ $? -ne 0 ]; then
    echo "Failed to write to $service_path"
    exit 4
fi
cat "$service_path"
systemctl daemon-reload
systemctl enable "$service_name"
systemctl start "$service_name"
