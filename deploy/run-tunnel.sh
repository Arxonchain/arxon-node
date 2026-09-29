#!/bin/sh
exec /root/cloudflared tunnel \
--credentials-file /etc/cloudflared/t.json \
--http-host-header 127.0.0.1 \
run --url http://127.0.0.1:8787 arxon-rpc
