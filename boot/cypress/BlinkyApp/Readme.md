### Blinking LED test application for MCUBoot Bootloader.

For more information about all project options use ../Readme.md (One level up)

**Description:**

Implements simple Blinky LED CM4 application to demonstrate MCUBoot Application operation in terms of BOOT and UPGRADE process.

It is started by MCUBoot Application which is running on CM0p.

Functionality:

* Blinks RED led with 2 different rates, depending on type of image - BOOT or UPGRADE.
* Prints debug info and version of itself to terminal at 115200 baud.
* Can be built for BOOT slot or UPGRADE slot of bootloader.
* UPGRADE slot can be located in SMIF area

**Currently supported platforms:**

* PSOC_064_2M
* PSOC_064_1M
* PSOC_064_512K
* PSOC_062_2M

**Pre-build action:**

Pre-build action is implemented for defining start address and size of flash, as well as RAM start address and size for BlinkyApp. 
These values are set by specifing following macros: `-DUSER_APP_SIZE`, `-DUSER_APP_START`, `-DRAM_SIZE`, `-DRAM_START` in makefile.

Pre-build action calls GCC preprocessor which intantiates defines for particular values in `BlinkyApp_template.ld`. 

Default values set for currently supported targets:
* PSOC_062_2M in `BlinkyApp.mk` to `-DUSER_APP_START=0x10018000`
* PSOC_064_2M, PSOC_064_1M, PSOC_064_512K in `BlinkyApp.mk` to `-DUSER_APP_START=0x10000000`

Start address of `BlinkyApp` is set to be used with Secure Boot enabled targets and corresponds to default policy settings provided with `cysecuretools` package.

**Building Multi-Image**

`BlinkyApp` can be built to use in multi-image bootloader configuration.

To get appropriate artifacts to use with multi image CypressBootloader, flag `MULTI_IMAGE=1`("Enabled") has to be passed to `make`. Default value is `MULTI_IMAGE=1`("Enabled").

*Note:* only 2 images are supported at the moment.

Slot sizes as well as their start addresses are defined by policy provisioned with CypressBootloader.

**Building an application:**

Root directory for build is **boot/cypress.**

The following command will build regular HEX file of a Blinky Application, BOOT slot:

    make app APP_NAME=BlinkyApp PLATFORM=PSOC_064_2M IMG_TYPE=BOOT

This have following defaults suggested:

    BUILDCFG=Debug
    IMG_TYPE=BOOT

To build UPGRADE image use following command:

    make app APP_NAME=BlinkyApp PLATFORM=PSOC_064_2M IMG_TYPE=UPGRADE
    
Example command-line for single-image:

    make app APP_NAME=BlinkyApp PLATFORM=PSOC_064_2M IMG_TYPE=BOOT MULTI_IMAGE=0

**Building an application in systems with SMIF:**

BlinkyApp can be build for platform configurations, where `UPGRADE` slot or slots are located in external memory. There is a build system flag to specify this explicitly - `SMIF_UPGRADE`. Passing this flag to build system leads to usage of `cysecuretools` policy file with flash map for SMIF. 

Example command-line for BOOT image in system with SMIF:

    make app APP_NAME=BlinkyApp PLATFORM=PSOC_064_2M IMG_TYPE=BOOT MULTI_IMAGE=1 SMIF_UPGRADE=1

Example command-line for UPGRADE image in system with SMIF:

    make app APP_NAME=BlinkyApp PLATFORM=PSOC_064_2M IMG_TYPE=UPGRADE MULTI_IMAGE=1 SMIF_UPGRADE=1

**Post-Build:**

Post build action is executed at compile time for `BlinkyApp`. In case of build for `PSOC_062_2M` platform it calls `imgtool` from `MCUBoot` scripts and adds signature to compiled image. In case build to use with CypressBootloader - `cysecuretools` package is used to add signature. This signature is then validated by CypressBootloader or MCUBoot application.

**How to program an application:**

Use any preferred tool for programming hex files.

Hex file names to use for programming:

`BlinkyApp` always produce build artifacts in 2 separate folders - `boot` and `upgrade`.

`BlinkyApp` built to run with `MCUBootApp` produces files with name BlinkyApp.hex in `boot` directory and `BlinkyApp_upgrade.hex` in `upgrade` folder. These files are ready to be flashed to the board.

`BlinkyApp` built to use with `CypressBootloader` produces artifacts, according to `cysecuretools` naming convention. Each folder - `boot` and `upgrade` contains files with _upgrade.hex and _unsigned.hex suffixes and plain name - BlinkyApp.hex. File with suffix `_upgrade.hex` always contains padding, required by MCUBoot for upgrade images. It's start address is also shifted to correspond start address of UPGRADE slot for image in policy file used for signing.

Files to use for programming are:

`BOOT` - boot/BlinkyApp.hex
`UPGRADE` - upgrade/BlinkyApp_upgrade.hex

**Flags:**
- `BUILDCFG` - configuration **Release** or **Debug**
- `MAKEINFO` - 0 (default) - less build info, 1 - verbose output of compilation.
- `HEADER_OFFSET` - 0 (default) - no offset of output hex file, 0x%VALUE% - offset for output hex file. Value 0x10000 is slot size MCUBoot Bootloader in this example.
- `IMG_TYPE` - `BOOT` (default) - build image for BOOT slot of MCUBoot Bootloader, `UPGRADE` - build image for UPGRADE slot of MCUBoot Bootloader.
- `MULTI_IMAGE` - `0` - set addresses for single image scheme. `1` (default) - set addresses for multiimage scheme.
- `SMIF_UPGRADE` - `0` (default) - use only internal flash. Set to `1` - build user application with `UPGRADE` slot located in SMIF. Corresponding policy from `cysecuretools` is used

**NOTE**: In case of `UPGRADE` image `HEADER_OFFSET` should be set to MCUBoot Bootloader slot size.

**Example terminal output:**

When user application programmed in BOOT slot:

    ===========================
    [BlinkyApp] BlinkyApp v1.0 [CM4]
    ===========================
    [BlinkyApp] GPIO initialized
    [BlinkyApp] UART initialized
    [BlinkyApp] Retarget I/O set to 115200 baudrate
    [BlinkyApp] Red led blinks with 1 sec period

When user application programmed in UPRADE slot and upgrade procedure was successful:

    ===========================
    [BlinkyApp] BlinkyApp v2.0 [+]
    ===========================

    [BlinkyApp] GPIO initialized
    [BlinkyApp] UART initialized
    [BlinkyApp] Retarget I/O set to 115200 baudrate
    [BlinkyApp] Red led blinks with 0.25 sec period
