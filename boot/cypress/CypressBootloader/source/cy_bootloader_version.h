/***************************************************************************//**
* \file cy_bootloader_version.h
* \version 1.00
*
* \brief
* This file provides definitions for Cypress Bootloader version number.
*
********************************************************************************
* \copyright
* Copyright 2016-2019, Cypress Semiconductor Corporation. All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/

#ifndef CY_BOOTLOADER_VERSION_H
#define CY_BOOTLOADER_VERSION_H

#ifndef CY_BOOTLOADER_MAJOR
#define CY_BOOTLOADER_MAJOR   (1u)
#endif

#ifndef CY_BOOTLOADER_MINOR
#define CY_BOOTLOADER_MINOR   (1u)
#endif

#ifndef CY_BOOTLOADER_REV
#define CY_BOOTLOADER_REV     (0u)
#endif

#ifndef CY_BOOTLOADER_BUILD
#define CY_BOOTLOADER_BUILD   (111u)
#endif

#define CY_BOOTLOADER_VERSION (((CY_BOOTLOADER_MAJOR & 0xFF) << 16u) | \
                               ((CY_BOOTLOADER_MINOR & 0xFF) << 8u) | \
                               (CY_BOOTLOADER_REV & 0xFF))

#endif /* CY_BOOTLOADER_VERSION_H */
