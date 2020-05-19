### "Secure" Blinking application to test milti-image in CyBootloader.

For more information about all project options use ../Readme.md (One level up)

**Description:**

Implements simple Blinky LED `CM0p` application to demonstrate milti-image configuration of CypressBootloader.

It is started by CypressBootloader which is also running on `CM0p`.

* Blinks RED led for 3 sec with 2 different rates, depending on type of image - BOOT or UPGRADE.
* Starts next application on `CM4`
* Prints debug info and version of itself to terminal at 115200 baud.
* Can be built for BOOT slot or UPGRADE slot of bootloader.
* Reads provisioning package to get policy.
* Controls CM4 access port according to the policy
* Applies memory and peripheral protections
* UPGRADE slot can be located in SMIF area

**Currently supported targets:**

* PSOC_064_2M
* PSOC_064_1M
* PSOC_064_512K

**Pre-build action:**

Pre-build action is implemented for defining start address and size of flash, as well as RAM start address and size for BlinkyApp. 
These values are set by specifing following macros: `-DUSER_APP_SIZE`, `-DUSER_APP_START`, `-DRAM_SIZE`, `-DRAM_START` in makefile.

Pre-build action calls GCC preprocessor which intantiates defines for particular values in `BlinkyApp_template.ld`. 

Default values set for currently supported targets:
* PSOC_064_2M, PSOC_064_1M, PSOC_064_512K in `BlinkyApp.mk` to `-DUSER_APP_START=0x10000000`

Start address of `BlinkyApp` is set to be used with Secure Boot enabled targets and corresponds to default policy settings provided with `cysecuretools` package.

**Building an application:**

Root directory for build is **boot/cypress.**

The following command will build regular HEX file of a Secure Blinky Application, BOOT slot:

    make app APP_NAME=SecureBlinkyApp PLATFORM=PSOC_064_2M IMG_TYPE=BOOT

This have following defaults suggested:

    BUILDCFG=Debug
    IMG_TYPE=BOOT

To build UPGRADE image use following command:

    make app APP_NAME=SecureBlinkyApp PLATFORM=PSOC_064_2M IMG_TYPE=UPGRADE
    
Example command-line for dual-image:

    make app APP_NAME=SecureBlinkyApp PLATFORM=PSOC_064_2M IMG_TYPE=BOOT MULTI_IMAGE=1

**Building an application in systems with SMIF:**

BlinkyApp can be build for platform configurations, where `UPGRADE` slot or slots are located in external memory. There is a build system flag to specify this explicitly - `SMIF_UPGRADE`. Passing this flag to build system leads to usage of `cysecuretools` policy file with flash map for SMIF. 

Example command-line for BOOT image in system with SMIF:

    make app APP_NAME=BlinkyApp PLATFORM=PSOC_064_2M IMG_TYPE=BOOT MULTI_IMAGE=1 SMIF_UPGRADE=1

Example command-line for UPGRADE image in system with SMIF:

    make app APP_NAME=BlinkyApp PLATFORM=PSOC_064_2M IMG_TYPE=UPGRADE MULTI_IMAGE=1 SMIF_UPGRADE=1

**Post-Build:**

Post build action is executed at compile time for `BlinkyApp`. In case of build for `PSOC_062_2M` platform it calls `imgtool` from `MCUBoot` scripts and adds signature to compiled image. In case build to use with CupressBootloader - `cysecuretools` package is used to add signature. This signature is then validated by CypressBootloader or MCUBoot application.

**How to program an application:**

**How to program an application:**

Use any preferred tool for programming hex files.

Hex file names to use for programming:

`SecureBlinkyApp` always produces build artifacts in 2 separate folders - `boot` and `upgrade`.

`SecureBlinkyApp` built to use with `CypressBootloader` produces artifacts, according to `cysecuretools` naming convention. Each folder - `boot` and `upgrade` contains files with `_upgrade.hex` and `_unsigned.hex` suffixes and plain name - BlinkyApp.hex. File with suffix `_upgrade.hex` always contains padding, required by MCUBoot for upgrade images. It's start address is also shifted to correspond start address of UPGRADE slot for image in policy file used for signing.

Files to use for programming are:

`BOOT` - boot/BlinkyApp.hex
`UPGRADE` - upgrade/BlinkyApp_upgrade.hex

**Flags:**
- `BUILDCFG` - configuration **Release** or **Debug**
- `MAKEINFO` - 0 (default) - less build info, 1 - verbose output of compilation.
- `HEADER_OFFSET` - 0 (default) - no offset of output hex file, 0x%VALUE% - offset for output hex file. Value 0x10000 is slot size CyBootloader in this example.
- `IMG_TYPE` - `BOOT` (default) - build image for BOOT slot of CyBootloader, `UPGRADE` - build image for UPGRADE slot of CyBootloader.
- `SMIF_UPGRADE` - `0` (default) - use only internal flash. Set to `1` - build user application with `UPGRADE` slot located in SMIF. Corresponding policy from `cysecuretools` is used

**NOTE**: In case of `UPGRADE` image `HEADER_OFFSET` should be set to Bootloader slot size

**Example terminal output:**

When user application programmed in BOOT slot:

    =============================================
    [SecureBlinkyApp] SecureBlinkyApp v1.0 [CM0p]
    =============================================

    [SecureBlinkyApp] GPIO initialized 
    [SecureBlinkyApp] UART initialized 
    [SecureBlinkyApp] Retarget I/O set to 115200 baudrate 
    [SecureBlinkyApp] Red led blinks SLOW for 3 sec
    [SecureBlinkyApp] Then CM4 app will be started
    [SecureBlinkyApp] CM4 app address 0x10020400
    [SecureBlinkyApp] Memory regions to protect:
    address: 0x101d0000; size 0x00010000;
    address: 0x080c0000; size 0x00040000;
    address: 0x080ec000; size 0x00004000;

When user application programmed in UPRADE slot and upgrade procedure was successful:

    =============================================
    [SecureBlinkyApp] SecureBlinkyApp v2.0 [+]
    =============================================

    [SecureBlinkyApp] GPIO initialized 
    [SecureBlinkyApp] UART initialized 
    [SecureBlinkyApp] Retarget I/O set to 115200 baudrate 
    [SecureBlinkyApp] Red led blinks FAST for 3 sec
    [SecureBlinkyApp] Then CM4 app will be started
    [SecureBlinkyApp] CM4 app address 0x10020400
    [SecureBlinkyApp] Memory regions to protect:
    address: 0x101d0000; size 0x00010000;
    address: 0x080c0000; size 0x00040000;
    address: 0x080ec000; size 0x00004000;
