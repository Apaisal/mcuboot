/* Manual version of auto-generated version. */

#ifndef __SYSFLASH_H__
#define __SYSFLASH_H__

#define FLASH_AREA_BOOTLOADER 0
#define FLASH_AREA_IMAGE_0 1
#define FLASH_AREA_IMAGE_1 2
#define FLASH_AREA_IMAGE_SCRATCH 3
#define FLASH_AREA_IMAGE_2 5
#define FLASH_AREA_IMAGE_3 6

#define CY_FLASH_ALIGN                      (128) // TODO: will fix it to CY_FLASH_SIZEOF_ROW (512) in PSoC6
#define CY_FLASH_DEVICE_BASE                (CY_FLASH_BASE)

#ifndef CY_BOOT_SCRATCH_SIZE
#define CY_BOOT_SCRATCH_SIZE                (0x1000)
#endif

#ifndef CY_BOOT_BOOTLOADER_SIZE
#define CY_BOOT_BOOTLOADER_SIZE             (0x20000)
#endif

#ifndef CY_BOOT_PRIMARY_1_SIZE
#define CY_BOOT_PRIMARY_1_SIZE              (0x10000)
#endif

#ifndef CY_BOOT_SECONDARY_1_SIZE
#define CY_BOOT_SECONDARY_1_SIZE            (0x10000)
#endif

// TODO: run-time multi-image
//#if (BOOT_IMAGE_NUMBER == 2) /* if dual-image */
#ifndef CY_BOOT_PRIMARY_2_SIZE
#define CY_BOOT_PRIMARY_2_SIZE              (0x10000)
#endif

#ifndef CY_BOOT_SECONDARY_2_SIZE
#define CY_BOOT_SECONDARY_2_SIZE            (0x10000)
#endif
//#endif

// TODO: run-time multi-image
//#if (MCUBOOT_IMAGE_NUMBER == 1)
/*
#define FLASH_AREA_IMAGE_PRIMARY(x)    (((x) == 0) ?          \
                                         FLASH_AREA_IMAGE_0 : \
                                         FLASH_AREA_IMAGE_0)
#define FLASH_AREA_IMAGE_SECONDARY(x)  (((x) == 0) ?          \
                                         FLASH_AREA_IMAGE_1 : \
                                         FLASH_AREA_IMAGE_1) */

//#elif (MCUBOOT_IMAGE_NUMBER == 2)

#define FLASH_AREA_IMAGE_PRIMARY(x)    (((x) == 0) ?          \
                                         FLASH_AREA_IMAGE_0 : \
                                        ((x) == 1) ?          \
                                         FLASH_AREA_IMAGE_2 : \
                                         255)
#define FLASH_AREA_IMAGE_SECONDARY(x)  (((x) == 0) ?          \
                                         FLASH_AREA_IMAGE_1 : \
                                        ((x) == 1) ?          \
                                         FLASH_AREA_IMAGE_3 : \
                                         255)

//#else
//#warning "Image slot and flash area mapping is not defined"
//#endif

#define CY_IMG_HDR_SIZE 0x400

#endif /* __SYSFLASH_H__ */
