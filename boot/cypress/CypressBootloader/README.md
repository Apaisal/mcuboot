### CypressBootloader

CypressBootloader is based on MCUBoot library and intended to be used with Cypress PSoC64 Secure Boot enabled chips. It is mandatory application on each PSoC64 device.

For more information about all project options use ../Readme.md (One level up)

**Description:**

Features implemented:
* Run on CM0p core
* Has debug prints to terminal on 115200
* Can validate image hash of 2 slots in flash memory BOOT and UPGRADE
* Starts image located in BOOT slot after validating signature
* Performs upgrade operation from UPGRADE slot to BOOT slot after UPGRADE image hash verification
* Supports Multi-Image processing

**Example flash map used for CypressBootloader on PSOC_064_2M in multi image configuration:**

    0x101D 0000 - 0x101D FE00 - CypressBootloader
    0x1000 0000 - 0x1001 0000 - BOOT slot of CypressBootloader
    0x1001 0000 - 0x1002 0000 - UPGRADE slot of CypressBootloader

All flash maps of slots are defined by policy. Default policies for supported targets can be found in `cysecuretools` package, used with CypressBootloader.

**Currently supported platfroms:**

* PSOC_064_2M
* PSOC_064_1M
* PSOC_064_512K

**How to build CypressBootloader:**

Root directory for build is **boot/cypress**.

The following command will build CypressBootloader HEX file:

    make app APP_NAME=CypressBootloader PLATFORM=PSOC_064_2M

Flags by defalt:

    BUILDCFG=Debug
    MAKEINFO=0
    
**Multi-Image Operation**

Multi-image operation considers upgrading and verification of more then one image on the device.

To enable multi-image operation `MCUBOOT_IMAGE_NUMBER` (mcuboot_config.h file) should be set to 2 (only dual-image is supported at the moment).

In multi-image operation (two images are considered for simplicity) CypressBootloader operates as following:

* Verifies Primary_1 and Primary_2 images;
* Verifies Secondary_1 and Secondary_2 images;
* Upgrades Secondary to Primary if valid images found;
* Boots image from Primary_1 slot only;
* Boots Primary_1 only if both - Primary_1 and Primary_2 are present and valid;

This ensures two dependent applications can be accepted by device only in case both images are valid.

**Default Flash map for Multi-Image operation:**

`0x101D0000 - 0x101DFE00` - CypressBootloader (PSoC-064 2M device is suggested here)

`0x10000000 - 0x10010000` - Primary_1 (BOOT) slot of Bootloader

`0x10010000 - 0x10020000` - Secondary_1 (UPGRADE) slot of Bootloader

`0x10020000 - 0x10030000` - Primary_2 (BOOT) slot of Bootloader

`0x10030000 - 0x10040000` - Secondary_2 (UPGRADE) slot of Bootloader

`0x10040000 - 0x10040100` - Scratch of Bootloader

These values are set as default in policies provided by `cysecuretools`.

**Multi-image policy**

To initiate CypressBootloader in multi-image mode, appropriate policy has to be used when provisioning device.

Those are supplied with [cysecuretools](https://pypi.org/project/cysecuretools/).

There are two firmware sections have to be present for each image and each has to contain "multi_image" : 1 or "multi_image" : 2 depending on which image is master.

If it is expected to use single-image only, then there should be regular polciy used with one firmware section in JSON and NO "multi_image" field has to be present.

**How to program CypressBootloader:**

CypressBootloader is programmed to the target board at provisioning stage. Refer to [PSoC® 64 Secure MCU Secure Boot SDK User Guide](https://www.cypress.com/documentation/software-and-drivers/psoc-64-secure-mcu-secure-boot-sdk-user-guide)

**Example terminal output:**

When user application programmed in BOOT slot:

    [INF] /******************************************************/
    [INF]  PSoC6 CyBootloader Application 1.1.0.420 
    [INF] /******************************************************/
    [INF]  
    [INF] CypressBootloader Started
    [INF] Single-image N = 1:
    [INF] Swap type: none
    [INF] User Application validated successfully
    [INF] Application at: 0x10000400

    ===========================
    [BlinkyApp] BlinkyApp v1.0 [CM4]
    ===========================

    [BlinkyApp] GPIO initialized 
    [BlinkyApp] UART initialized 
    [BlinkyApp] Retarget I/O set to 115200 baudrate 
    [BlinkyApp] Red led blinks with 1 sec period