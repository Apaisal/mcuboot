#!/bin/bash

############################
# Linux specific definitions
MODUS_TOOLCHAIN_PATH="${MODUS_TOOLCHAIN_PATH:-$HOME/ModusToolbox/tools_2.0/gcc-7.2.1}"

############################
# Setup environment variables 
#
function setup_environment {
    echo "[INFO] Setting environment"
    #export http_proxy=http://csj-mwg01.cysemi.com:8080
    #export https_proxy=$http_proxy
    TOOLCHAIN_PATH=$MODUS_TOOLCHAIN_PATH
}


############################
# Prepare to build
#
function prepare_to_build {    

    [[ -d ${ROOT_DIR}/venv ]] || cmd_check virtualenv --python=python3 "$ROOT_DIR/venv" 
   
    source ${ROOT_DIR}/venv/bin/activate
    
    echo "[DEBUG] Python path: $(which python)"

    [[ -d ${ROOT_DIR}/venv/lib/python3.6/site-packages/serial ]] || cmd_check pip install pyserial

    cmd_check pip install --upgrade --force-reinstall git+http://git-ore.aus.cypress.com/repo/cysecuretools.git@$CY_SECURETOOLS_BRANCH -U

    cmd_check pip install --upgrade --force-reinstall git+http://git-ore.aus.cypress.com/repo/pyocd.git@$PYOCD_BRANCH -U
   
    local cy_secure_tools_path=$(python -c "import cysecuretools; import os; print(os.path.dirname(os.path.dirname(cysecuretools.__file__)))")
    echo -e "[INFO]: CY_SEC_TOOLS ${cy_secure_tools_path}"
    
    cmd_check cp -R ${ROOT_DIR}/../../../../keys ${cy_secure_tools_path}/cysecuretools/targets/cy8ckit_064x0s2_4343w/ 
    cmd_check cp -R ${ROOT_DIR}/../../../../keys ${cy_secure_tools_path}/cysecuretools/targets/cy8cproto_064s1_sb/
    cmd_check cp -R ${ROOT_DIR}/../../../../keys ${cy_secure_tools_path}/cysecuretools/targets/cy8cproto_064s2_sb/
    cmd_check cp -R ${ROOT_DIR}/../../../../keys ${cy_secure_tools_path}/cysecuretools/targets/cyb06xx5/
    cmd_check cp -R ${ROOT_DIR}/../../../../keys ${cy_secure_tools_path}/cysecuretools/targets/cyb06xx7/
    cmd_check cp -R ${ROOT_DIR}/../../../../keys ${cy_secure_tools_path}/cysecuretools/targets/cyb06xxa/
}

############################
# Install Cy Python module for repo
#
function install_cy_pymodule {
    local _name=$1
    local _url=$2
    local _branch=$3
    
    local _dir_loc="$ROOT_DIR/${_name}_loc"

    if [ ! -d "$_dir_loc" ]; then
        echo -e "${GREEN}[GIT] Cloning $_url... ${NC}"
        cmd_check git clone $_url $_dir_loc > /dev/null 2>&1
    fi
    
    pushd "$_dir_loc"
        cmd_check git checkout --force $_branch 
        echo -e "${GREEN}[python] setup.py running... ${NC}"
        cmd_check python setup.py install > /dev/null 2>&1
    popd
}

############################
# Fetch inputs before build
#
function fetch_inputs {
    echo -e "\n[INFO] Fetching build inputs..."
}



############################
# Collect build outputs
#
function collect_outputs {
    echo "[INFO] Aggregating build aritfacts..."

    collect_common
}

