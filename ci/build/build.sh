#!/bin/bash

set -$e${DEBUG+xv}

cd $(dirname "${BASH_SOURCE[0]}")

source ./common.sh
detect_os
source ${os}/build.sh

setup_environment
clean_up
fetch_inputs
prepare_to_build
build $@
collect_outputs