/* Manual version of auto-generated version. */

#ifndef __SYSFLASH_H__
#define __SYSFLASH_H__

#include <stdint.h>
#include "cy_syslib.h"

#define FLASH_DEVICE_INTERNAL_FLASH         (0x7F)

#define FLASH_AREA_BOOTLOADER               (0)
#define FLASH_AREA_IMAGE_0                  (1)
#define FLASH_AREA_IMAGE_1                  (2)
#define FLASH_AREA_IMAGE_SCRATCH            (3)
#define FLASH_AREA_IMAGE_2                  (5)
#define FLASH_AREA_IMAGE_3                  (6)

/* This defines if External Flash (SMIF) will be used for Upgrade Slots */
/* #define CY_BOOT_USE_EXTERNAL_FLASH */

/* use PDL-defined offset or one from SMFI config */
#define CY_SMIF_BASE_MEM_OFFSET             (0x18000000)

#define CY_FLASH_ALIGN                      CY_FLASH_SIZEOF_ROW
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


/*
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
*/

__STATIC_INLINE uint8_t FLASH_AREA_IMAGE_PRIMARY(uint32_t areaID)
{
    uint8_t result;

    if (0U == areaID)
    {
        result = FLASH_AREA_IMAGE_0;
    }
    else
    if (1U == areaID)
    {
        result = FLASH_AREA_IMAGE_2;
    }
    else
    {
        result = 0xFF;
    }

    return result;
}

__STATIC_INLINE uint8_t FLASH_AREA_IMAGE_SECONDARY(uint32_t areaID)
{
    uint8_t result;

    if (0U == areaID)
    {
        result = FLASH_AREA_IMAGE_1;
    }
    else
    if (1U == areaID)
    {
        result = FLASH_AREA_IMAGE_3;
    }
    else
    {
        result = 0xFF;
    }

    return result;
}

//#else
//#warning "Image slot and flash area mapping is not defined"
//#endif

#define CY_IMG_HDR_SIZE 0x400

#endif /* __SYSFLASH_H__ */
