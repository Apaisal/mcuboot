#!/bin/bash

############################
# Common definitions

# Root directory of repository. Parent to this script
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

MAJOR_VERSION=${MAJOR_VERSION:-1}
MINOR_VERSION=${MINOR_VERSION:-1}
PATCH_VERSION=${PATCH_VERSION:-0}
BUILD_NUMBER=${BUILD_NUMBER:-0}

CY_BOOTLOADER_MAJOR=${CY_BOOTLOADER_MAJOR:-1}
CY_BOOTLOADER_MINOR=${CY_BOOTLOADER_MINOR:-1}
CY_BOOTLOADER_REV=${CY_BOOTLOADER_REV:-0}
CY_BOOTLOADER_BUILD=${CY_BOOTLOADER_BUILD:-424}


# Build directory
BUILD_DIR="${ROOT_DIR}/ci/build"

# Cy boot directory
BOOT_CY_DIR="${ROOT_DIR}/boot/cypress"

# Input directory 
INPUT_DIR="${INPUT_DIR:-${ROOT_DIR}/input}"

# Output directory 
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/output}"

# Deploy directory for uploading build assets 
DEPLOY_DIR="${DEPLOY_DIR:-${ROOT_DIR}/deploy}"

# Deploy directory for build outputs
DEVELOP_DIR="${DEPLOY_DIR:-${ROOT_DIR}/develop}"

YELLOW='\033[1;36m'
NC='\033[0m' # No Color
BLUE='\033[1;32m'


############################
# Run command and check return status 
#
function cmd_check {
    echo -e "\n${YELLOW}[RUN] ${@}${NC}"
    "$@" || { echo "[ERROR] $1" >&2; exit 1; }
}

############################
# Detect the current operating system
# The returned OS value is compatible with cloud manifest 'os' attribute:
# One of: windows linux macos
#
function detect_os {
    local kernel="$(uname -s)"
    case "${kernel}" in
        Linux*)     os=linux;;
        Darwin*)    os=macos;;
        CYGWIN*)    os=windows;;
        MINGW*)     os=windows;;
        MSYS*)      os=windows;;
        *)          os="UNKNOWN:${kernel}"
    esac
    echo ${os}
}

############################
# Cross-platform symlink function. With one parameter, it will check
# whether the parameter is a symlink. With two parameters, it will create
# a symlink to a file or directory, with syntax: link $linkname $target
#
function link {
    echo "[INFO] creating link: $1 -> $2"
    if [[ -z "$2" ]]; then
        # Link-checking mode.
        #if windows; then
        if [[ ${os} = windows ]]; then
            fsutil reparsepoint query "$1" > /dev/null
        else
            [[ -h "$1" ]]
        fi
    else
        # Link-creation mode.
        #if windows; then
        if [[ ${os} = windows ]]; then
            # Windows needs to be told if it's a directory or not. Infer that.
            # convert path to windows
            local pth1=$(path_cygwin_to_win "$1")
            local pth2=$(path_cygwin_to_win "$2")
            if [[ -d "$2" ]]; then
                cmd <<< "mklink /D \"${pth1}\" \"${pth2}\"" > /dev/null
                
            else
                cmd <<< "mklink \"${pth1}\" \"${pth2}\"" > /dev/null
            fi
        else
            # You know what? I think ln's parameters are backwards.
            ln -s "$2" "$1"
        fi
    fi
}


############################
# Build 
#
function build {

    pushd "$BOOT_CY_DIR"
    
    #CURDIR=$(pwd | cygpath -m -f -)
    CURDIR=.
    #local cy_secure_tools_path=$(python -c "import cysecuretools; import os; print(os.path.dirname(os.path.dirname(cysecuretools.__file__)))")
    #export CY_SEC_TOOLS_PATH=$(path_win_backslash $cy_secure_tools_path )

    unset_build_app_vars
    
    possible_parameters=(APP_NAME APP_SUFX PLATFORM IMG_TYPE MULTI_IMAGE MAKEINFO BUILDCFG CURDIR TOOLCHAIN_PATH POST_BUILD TARGET SMIF_UPGRADE)
    
    for input_param in "$@"
    do
        IFS='=' read -ra param_value <<< "$input_param"
        for param_name in ${possible_parameters[*]}
        do
            if [[ ${param_value[0]} == ${param_name} ]]
            then
                printf -v ${param_name} "${param_value[1]}" 
            fi
        done      
    done

    
    build_app

    popd
}


############################
# Remove a link, cross-platform.
#
function rmlink {
    if [[ ${os} = windows ]]; then
        # Again, Windows needs to be told if it's a file or directory.
        if [[ -d "$1" ]]; then
            rmdir "$1";
        else
            rm "$1"
        fi
    else
        rm "$1"
    fi
}


############################
# Convert Cygwin path to Windows
#
function path_cygwin_to_win {
    echo $(cygpath -w ${1})
}

############################
# Convert Cygwin path to Windows (backslahes)
#
function path_cygwin_to_win_backslash {
    echo $(cygpath -m ${1})
}

############################
# Convert Cygwin path to Windows
# and add extra backslahes
#
function correct_filepath_win {
    local pth=$(path_cygwin_to_win "$1")
    echo "$pth" | sed -e 's/\\/\\\\/g'
}

############################
# Convert Windows path to Cygwin 
#
function path_win_to_cygpath {
    echo $(cygpath --unix ${1})
}

############################
# Unset build application variables
#
function unset_build_app_vars {
    unset APP_NAME
    unset APP_SUFX
    unset HEX_NAME
    unset SLOT
    unset TARGET
    unset PLATFORM
    unset BUILDCFG
    unset IMG_TYPE
    unset MULTI_IMAGE
    unset MAKEINFO
    unset POST_BUILD
    unset HEADER_OFFSET
    unset DEFINES_USER
}

############################
# Build application variables
#
function build_app {     
    local make_args="APP_NAME=${APP_NAME}"
    
    if [[ $APP_NAME == "CypressBootloader" ]]
    then
        
        export APP_NAME=CypressBootloader
        export HEX_NAME=CypressBootloader_CM0p
        export DEFINES_USER='-DCY_BOOTLOADER_MAJOR=${CY_BOOTLOADER_MAJOR} -DCY_BOOTLOADER_MINOR=${CY_BOOTLOADER_MINOR} -DCY_BOOTLOADER_REV=${CY_BOOTLOADER_REV} -DCY_BOOTLOADER_BUILD=${CY_BOOTLOADER_BUILD}'
        export SLOT='' 
        
    else
    
        export SLOT=`echo $IMG_TYPE | awk '{print tolower($0)}'`
        if [ $SLOT == 'upgrade' ]; then export SUFX=_$SLOT; else export SUFX=''; fi
        if [ ! -z $MULTI_IMAGE ]; then if [ $MULTI_IMAGE -eq 0 ] && [ $SMIF_UPGRADE -eq 0 ]; then export APP_SUFX=''; export APP_BUILD_OPTIONS+='MULTI_IMAGE=0 '; fi; fi
        if [ ! -z $HEADER_OFFSET ]; then export APP_BUILD_OPTIONS+=HEADER_OFFSET=$HEADER_OFFSET; fi
        if [ -z $HEX_NAME ]; then export HEX_NAME=$APP_NAME; fi
    
    fi

    echo -e "${BLUE}================================================================================================="
    echo -e "=== Building $APP_NAME application..."
    echo -e "=== PLATFORM = $PLATFORM, BUILDCFG = $BUILDCFG, MAKEINFO = $MAKEINFO"
    echo -e "=================================================================================================${NC}"
        
    [ -z ${TARGET+x} ] || { make_args="${make_args} TARGET=$TARGET"; }
    [ -z ${PLATFORM+x} ] || { make_args="${make_args} PLATFORM=$PLATFORM"; }
    [ -z ${BUILDCFG+x} ] || { make_args="${make_args} BUILDCFG=$BUILDCFG"; }
    [ -z ${MAKEINFO+x} ] || { make_args="${make_args} MAKEINFO=$MAKEINFO"; }
    [ -z ${MULTI_IMAGE+x} ] || { make_args="${make_args} MULTI_IMAGE=$MULTI_IMAGE"; }
    [ -z ${IMG_TYPE+x} ] || { make_args="${make_args} IMG_TYPE=$IMG_TYPE"; }
    [ -z ${POST_BUILD+x} ] || { make_args="${make_args} POST_BUILD=$POST_BUILD"; }
    [ -z ${TOOLCHAIN_PATH+x} ] || { make_args="${make_args} TOOLCHAIN_PATH=$TOOLCHAIN_PATH"; }
    [ -z ${CURDIR+x} ] || { make_args="${make_args} CURDIR=$CURDIR"; }
    [ -z ${SMIF_UPGRADE+x} ] || { make_args="${make_args} SMIF_UPGRADE=$SMIF_UPGRADE"; }
    
    cmd_check make -j4 clean APP_NAME=$APP_NAME
    cmd_check make -j4 app $make_args
}

############################
# Clean up previous build 
#
function clean_up {
    printf "\n[INFO] removing previous build outputs\n"
    cmd_check rm -rf "${DEPLOY_DIR}"
    cmd_check mkdir -p "${DEPLOY_DIR}"

    cmd_check rm -rf "${DEVELOP_DIR}"
    cmd_check mkdir -p "${DEVELOP_DIR}"

    cmd_check rm -rf "${INPUT_DIR}"
    cmd_check mkdir -p "${INPUT_DIR}"
}

############################
# Prepare to build
#
function prepare_to_build_common {
    echo "[INFO] Preparing to build..."
   
}

############################
# Create zip archive with SDK content
#
function zip_content {
    local src_dir=$1
    local dst_zip=$2
    (cd "$(dirname "${src_dir}")" && zip -rqX - "$(basename "${src_dir}")") > "${dst_zip}"
}

############################
# Create zip archive from folder
#
function zip_folder {
    local src_dir=$1
    local dst_zip=$2
    
    pushd "$src_dir"
        cmd_check zip -rX "$dst_zip" *
    popd
}

############################
# Create tar.gz archive from folder
#
function targz_folder {
    local src_dir=$1
    local dst_zip=$2
    
    pushd "$src_dir"
        cmd_check tar -zcvf "$dst_zip" .
    popd
}

############################
# Fetch artifact from the remote http location
#
function fetch_artifact {
    local src=$1
    local dst=$2

    # Set WGET_DST global variable during the wget execution
    # so the incomplete artifact can be removed on script failure
    WGET_DST="${dst}"
    echo "[INFO] Downloading $(basename "${dst}")"
    [[ -f "${dst}" ]] || { cmd_check wget ${WGET_OPTS} "${src}" -O "${dst}"; }
    WGET_DST=
}

############################
# Fetch asset build number from the remote URL txt
#
# Usage:
# fetch_build_number http://iot-webserver.aus.cypress.com/projects/iot_release/ASSETS/repo/<project_name>/<branch>/<pipeline_iid>/_bld_info.txt
#
function fetch_asset_build_number {
    local build_number=$(wget -qO- "$1" | cut -f2 -d" ")
    echo ${build_number}
}

############################
# Fetch build number from the remote URL txt
#
# Usage:
# fetch_build_number http://jenkins-job-url/artifact/build_number.txt
#
function fetch_build_number {
    local build_number=$(wget -qO- "$1")
    echo ${build_number}
}

############################
# Fetch Jenkins build number using JSON API
#
# Usage:
# fetch_jenkins_build_number http://jenkins/job/url
#
function fetch_jenkins_build_number {
    local build_number=$(fetch_build_number "$1/lastSuccessfulBuild/buildNumber")
    echo ${build_number}
}

############################
# Fetch deployed asset artifacts
#
function fetch_deploy_asset {
    local assets_url=$1
    local assets_branch=$2 
    local pkg_build=$3
    local pkg_name=$4
    if [ $pkg_build -ge 0 ]; then 
        local _build_number=$pkg_build

        if [ $_build_number -eq 0 ]; then
            _build_number=Latest
        fi

        local _build_url=$assets_url/$assets_branch/$_build_number

        _build_number=$(fetch_asset_build_number "$_build_url/_bld_info.txt")
        [ -z "$_build_number" ] && { echo "[ERROR] Unable to determine build number for $assets_url asset" >&2; exit 1; }
        
        echo "[INFO] Build number: ${_build_number}"

        local _build_artifacts_url=${_build_url}/deploy/$pkg_name

        fetch_artifact ${_build_artifacts_url} "${INPUT_DIR}/$pkg_name"
    fi
}


############################
# Collect artifacts common for all OSs
#
function collect_common {
    echo -e $APPNAME
    
    
    if [[ $APP_NAME == "CypressBootloader" ]]
    then
 
        cmd_check mkdir -p ${ROOT_DIR}/deploy/$PLATFORM/$APP_NAME/$BUILDCFG
        cmd_check mkdir -p ${ROOT_DIR}/develop/$PLATFORM/$APP_NAME/$BUILDCFG
        
        # Collect CypressBootloader for ${PLATFORM} develop
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/*.hex ${ROOT_DIR}/develop/$PLATFORM/$APP_NAME/$BUILDCFG/
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/*.lst ${ROOT_DIR}/develop/$PLATFORM/$APP_NAME/$BUILDCFG/
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/*.elf ${ROOT_DIR}/develop/$PLATFORM/$APP_NAME/$BUILDCFG/
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/*.map ${ROOT_DIR}/develop/$PLATFORM/$APP_NAME/$BUILDCFG/
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/*.jwt ${ROOT_DIR}/develop/$PLATFORM/$APP_NAME/$BUILDCFG/
        
        # Collect Signed application for ${PLATFORM} deploy
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/$HEX_NAME.hex ${ROOT_DIR}/deploy/$PLATFORM/$APP_NAME/$BUILDCFG/
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/*.jwt ${ROOT_DIR}/deploy/$PLATFORM/$APP_NAME/$BUILDCFG/
        

    else

        cmd_check mkdir -p ${ROOT_DIR}/deploy/$PLATFORM/$APP_NAME$APP_SUFX/$BUILDCFG/$SLOT
        cmd_check mkdir -p ${ROOT_DIR}/develop/$PLATFORM/$APP_NAME$APP_SUFX/$BUILDCFG/$SLOT        
        
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/$SLOT/*.hex  ${ROOT_DIR}/develop/$PLATFORM/$APP_NAME$APP_SUFX/$BUILDCFG/$SLOT/
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/$SLOT/*.lst  ${ROOT_DIR}/develop/$PLATFORM/$APP_NAME$APP_SUFX/$BUILDCFG/$SLOT/
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/$SLOT/*.elf  ${ROOT_DIR}/develop/$PLATFORM/$APP_NAME$APP_SUFX/$BUILDCFG/$SLOT/
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/$SLOT/*.map  ${ROOT_DIR}/develop/$PLATFORM/$APP_NAME$APP_SUFX/$BUILDCFG/$SLOT/

        # Collect App for deploy
        cmd_check cp -r ${ROOT_DIR}/boot/cypress/$APP_NAME/out/$PLATFORM/$BUILDCFG/$SLOT/${HEX_NAME}_unsigned.hex ${ROOT_DIR}/deploy/$PLATFORM/$APP_NAME$APP_SUFX/$BUILDCFG/$SLOT/${HEX_NAME}_unsigned.hex
    fi
    
}
