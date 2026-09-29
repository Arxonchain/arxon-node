#!/bin/sh
exec /root/arxon-node/target/release/arxon-node \
--base-path /root/arxon-zk \
--chain dev \
--alice \
--validator \
--node-key-file /root/nk \
--rpc-cors all
