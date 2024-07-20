#!/bin/sh

wgu_dir="${HOME}/.wgu"

exec /usr/local/bin/wgu \
  -config "${wgu_dir}/wgu.conf" \
  -A 2> "${wgu_dir}/wgu.log"
