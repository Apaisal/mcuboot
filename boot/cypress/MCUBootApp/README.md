### Port of MCUBoot library to be used with Cypress targets

**Solution Description**

Given solution demonstrates operation of MCUBoot on Cypress' PSoC6 device.

There are two applications implemented:
* MCUBootApp - PSoC6 MCUBoot-based bootloading application;
* BlinkyApp - simple PSoC6 blinking LED application which is a target of BOOT/UPGRADE;

The demonstration device is CY8CPROTO-062-4343W board which is PSoC6 device with 2M of Flash available.

The default flash map implemented is the following:

* [0x10000000, 0x10018000] - MCUBootApp (bootloader) area;
* [0x10018000, 0x10028000] - primary slot for BlinkyApp;
* [0x10028000, 0x10038000] - secondary slot for BlinkyApp;
* [0x10038000, 0x10039000] - scratch area;

MCUBootApp checks image integrity with SHA256, image authenticity with EC256 digital signature verification and uses completely SW implementation of cryptographic functions based on mbedTLS Library.

**Downloading Solution's Assets**

There is a set assets required:

* MCUBooot Library (root repository)
* PSoC6 HAL Library
* PSoC6 Peripheral Drivers Library (PDL)
* mbedTLS Cryptographic Library

To get submodules - run the following command:

    git submodule update --init --recursive

**Building Solution**

This folder contains make files infrastructure for building MCUBoot Bootloader. Same approach used in sample BlinkyLedApp application. To build solution run following command:

    make app APP_NAME=MCUBootApp PLATFORM=PSOC_062_2M BUILDCFG=Debug

Instructions on how to build and upload Bootloader and sample image are located is `Readme.md` files in corresponding folders.

Root directory for build is **boot/cypress.**

**Currently supported platforms:**

* PSOC_062_2M

**Build environment troubleshooting:**

Regular shell/terminal combination on Linux and MacOS.

On Windows:

* Cygwin
* Msys2

Also IDE may be used:
* Eclipse / ModusToolbox ("makefile project from existing source")

*Make* - make sure it is added to system's `PATH` variable and correct path is first in the list;

*Python/Python3* - make sure you have correct path referenced in `PATH`;

*Msys2* - to use systems PATH navigate to msys2 folder, open `msys2_shell.cmd`, uncomment set `MSYS2_PATH_TYPE=inherit`, restart MSYS2 shell.

This will iherit system's PATH so should find `python3.7` installed in regular way as well as imgtool and its dependencies.

