#!/bin/bash
set -e -u -o pipefail

VERSION=0.5.0

curl -L https://github.com/maexrakete/culper/releases/download/${VERSION}/culper --output /usr/bin/culper
chmod +x /usr/bin/culper
