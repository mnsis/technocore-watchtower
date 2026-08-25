#!/bin/sh
set -eu

output_dir="dist"
rm -rf "$output_dir"
mkdir -p "$output_dir/static"
cp index.html events.html rooms.html "$output_dir/"
cp ../web/static/app.css ../web/static/app.js ../web/static/live.js \
  ../web/static/watchtower-mark.svg "$output_dir/static/"
