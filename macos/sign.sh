#!/bin/sh
codesign --force --sign - --timestamp=none --entitlements=macos/vz.entitlements $1
