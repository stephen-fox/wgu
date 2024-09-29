#!/bin/sh

wgu_dir="${HOME}/.wgu"

exec /usr/local/bin/wgu \
  up -A "${wgu_dir}/wgu.conf" \
  2> "${wgu_dir}/wgu.log"
