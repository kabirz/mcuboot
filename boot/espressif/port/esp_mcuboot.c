/*
 * Copyright (c) 2021 Espressif Systems (Shanghai) Co., Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdlib.h>

#include "mcuboot_config/mcuboot_logging.h"
#include "flash_map_backend/flash_map_backend.h"
#include "sysflash/sysflash.h"
#include "bootutil/bootutil.h"

#include "esp_err.h"
#include "bootloader_flash.h"
#include "bootloader_flash_priv.h"

#ifndef ARRAY_SIZE
#  define ARRAY_SIZE(arr)           (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef MIN
#  define MIN(a, b)                 (((a) < (b)) ? (a) : (b))
#endif

#ifndef ALIGN_UP
#  define ALIGN_UP(num, align)      (((num) + ((align) - 1)) & ~((align) - 1))
#endif

#ifndef ALIGN_DOWN
#  define ALIGN_DOWN(num, align)    ((num) & ~((align) - 1))
#endif

#ifndef ALIGN_OFFSET
#  define ALIGN_OFFSET(num, align)  ((num) & ((align) - 1))
#endif

#ifndef IS_ALIGNED
#  define IS_ALIGNED(num, align)    (ALIGN_OFFSET((num), (align)) == 0)
#endif

#define FLASH_BUFFER_SIZE           256 /* SPI Flash block size */

_Static_assert(IS_ALIGNED(FLASH_BUFFER_SIZE, 4), "Buffer size for SPI Flash operations must be 4-byte aligned.");

#define BOOTLOADER_START_ADDRESS 0x1000
#define BOOTLOADER_SIZE CONFIG_ESP_BOOTLOADER_SIZE
#define APPLICATION_PRIMARY_START_ADDRESS CONFIG_ESP_APPLICATION_PRIMARY_START_ADDRESS
#define APPLICATION_SECONDARY_START_ADDRESS CONFIG_ESP_APPLICATION_SECONDARY_START_ADDRESS
#define APPLICATION_SIZE CONFIG_ESP_APPLICATION_SIZE
#define SCRATCH_OFFSET CONFIG_ESP_SCRATCH_OFFSET
#define SCRATCH_SIZE CONFIG_ESP_SCRATCH_SIZE

extern int ets_printf(const char *fmt, ...);

static const struct flash_area bootloader = {
    .fa_id = FLASH_AREA_BOOTLOADER,
    .fa_device_id = FLASH_DEVICE_INTERNAL_FLASH,
    .fa_off = BOOTLOADER_START_ADDRESS,
    .fa_size = BOOTLOADER_SIZE,
};

static const struct flash_area primary_img0 = {
    .fa_id = FLASH_AREA_IMAGE_PRIMARY(0),
    .fa_device_id = FLASH_DEVICE_INTERNAL_FLASH,
    .fa_off = APPLICATION_PRIMARY_START_ADDRESS,
    .fa_size = APPLICATION_SIZE,
};

static const struct flash_area secondary_img0 = {
    .fa_id = FLASH_AREA_IMAGE_SECONDARY(0),
    .fa_device_id = FLASH_DEVICE_INTERNAL_FLASH,
    .fa_off = APPLICATION_SECONDARY_START_ADDRESS,
    .fa_size = APPLICATION_SIZE,
};

static const struct flash_area scratch_img0 = {
    .fa_id = FLASH_AREA_IMAGE_SCRATCH,
    .fa_device_id = FLASH_DEVICE_INTERNAL_FLASH,
    .fa_off = SCRATCH_OFFSET,
    .fa_size = SCRATCH_SIZE,
};

static const struct flash_area *s_flash_areas[] = {
    &bootloader,
    &primary_img0,
    &secondary_img0,
    &scratch_img0,
};

static const struct flash_area *prv_lookup_flash_area(uint8_t id) {
    for (size_t i = 0; i < ARRAY_SIZE(s_flash_areas); i++) {
        const struct flash_area *area = s_flash_areas[i];
        if (id == area->fa_id) {
            return area;
        }
    }
    return NULL;
}

int flash_area_open(uint8_t id, const struct flash_area **area_outp)
{
    MCUBOOT_LOG_DBG("%s: ID=%d", __func__, (int)id);
    const struct flash_area *area = prv_lookup_flash_area(id);
    *area_outp = area;
    return area != NULL ? 0 : -1;
}

void flash_area_close(const struct flash_area *area)
{

}

static bool aligned_flash_read(uintptr_t addr, void *dest, size_t size)
{
    if (IS_ALIGNED(addr, 4) && IS_ALIGNED((uintptr_t)dest, 4) && IS_ALIGNED(size, 4)) {
        /* A single read operation is enough when when all parameters are aligned */

        return bootloader_flash_read(addr, dest, size, true) == ESP_OK;
    }

    const uint32_t aligned_addr = ALIGN_DOWN(addr, 4);
    const uint32_t addr_offset = ALIGN_OFFSET(addr, 4);
    uint32_t bytes_remaining = size;
    uint8_t read_data[FLASH_BUFFER_SIZE] = {0};

    /* Align the read address to 4-byte boundary and ensure read size is a multiple of 4 bytes */

    uint32_t bytes = MIN(bytes_remaining + addr_offset, sizeof(read_data));
    if (bootloader_flash_read(aligned_addr, read_data, ALIGN_UP(bytes, 4), true) != ESP_OK) {
        return false;
    }

    /* Skip non-useful data which may have been read for adjusting the alignment */

    uint32_t bytes_read = bytes - addr_offset;
    memcpy(dest, &read_data[addr_offset], bytes_read);

    bytes_remaining -= bytes_read;

    /* Read remaining data from Flash in case requested size is greater than buffer size */

    uint32_t offset = bytes;

    while (bytes_remaining != 0) {
        bytes = MIN(bytes_remaining, sizeof(read_data));
        if (bootloader_flash_read(aligned_addr + offset, read_data, ALIGN_UP(bytes, 4), true) != ESP_OK) {
            return false;
        }

        memcpy(&((uint8_t *)dest)[bytes_read], read_data, bytes);

        offset += bytes;
        bytes_read += bytes;
        bytes_remaining -= bytes;
    }

    return true;
}

int flash_area_read(const struct flash_area *fa, uint32_t off, void *dst,
                    uint32_t len)
{
    if (fa->fa_device_id != FLASH_DEVICE_INTERNAL_FLASH) {
        return -1;
    }

    const uint32_t end_offset = off + len;
    if (end_offset > fa->fa_size) {
        MCUBOOT_LOG_ERR("%s: Out of Bounds (0x%x vs 0x%x)", __func__, end_offset, fa->fa_size);
        return -1;
    }

    bool success = aligned_flash_read(fa->fa_off + off, dst, len);
    if (!success) {
        MCUBOOT_LOG_ERR("%s: Flash read failed", __func__);

        return -1;
    }

    return 0;
}

int flash_area_write(const struct flash_area *fa, uint32_t off, const void *src,
                     uint32_t len)
{
    uint32_t write_len = len, write_data = 0;
    void *write_ptr = (void *)src;
    if (fa->fa_device_id != FLASH_DEVICE_INTERNAL_FLASH) {
        return -1;
    }

    const uint32_t end_offset = off + len;

    if (end_offset > fa->fa_size) {
        MCUBOOT_LOG_ERR("%s: Out of Bounds (0x%x vs 0x%x)", __func__, end_offset, fa->fa_size);
        return -1;
    }

    const uint32_t start_addr = fa->fa_off + off;
    MCUBOOT_LOG_DBG("%s: Addr: 0x%08x Length: %d", __func__, (int)start_addr, (int)len);
    if (len < 4) {
        flash_area_read(fa, start_addr, &write_data, sizeof(uint32_t));
        memcpy(&write_data, src, len);
        write_ptr = (void *)&write_data;
        write_len = sizeof(uint32_t);
    }

    if (bootloader_flash_write(start_addr, write_ptr, write_len, false) != ESP_OK) {
        MCUBOOT_LOG_ERR("%s: Flash write failed", __func__);
        return -1;
    }
#if VALIDATE_PROGRAM_OP
    if (memcmp((void *)addr, src, len) != 0) {
        MCUBOOT_LOG_ERR("%s: Program Failed", __func__);
        assert(0);
    }
#endif

    return 0;
}

int flash_area_erase(const struct flash_area *fa, uint32_t off, uint32_t len)
{
    if (fa->fa_device_id != FLASH_DEVICE_INTERNAL_FLASH) {
        return -1;
    }

    if ((len % FLASH_SECTOR_SIZE) != 0 || (off % FLASH_SECTOR_SIZE) != 0) {
        MCUBOOT_LOG_ERR("%s: Not aligned on sector Offset: 0x%x Length: 0x%x", __func__,
                    (int)off, (int)len);
        return -1;
    }

    const uint32_t start_addr = fa->fa_off + off;
    MCUBOOT_LOG_DBG("%s: Addr: 0x%08x Length: %d", __func__, (int)start_addr, (int)len);

    if (bootloader_flash_erase_range(start_addr, len) != ESP_OK) {
        MCUBOOT_LOG_ERR("%s: Flash erase failed", __func__);
        return -1;
    }
#if VALIDATE_PROGRAM_OP
    for (size_t i = 0; i < len; i++) {
        uint8_t *val = (void *)(start_addr + i);
        if (*val != 0xff) {
            MCUBOOT_LOG_ERR("%s: Erase at 0x%x Failed", __func__, (int)val);
            assert(0);
        }
    }
#endif

    return 0;
}

size_t flash_area_align(const struct flash_area *area)
{
    return 4;
}

uint8_t flash_area_erased_val(const struct flash_area *area)
{
    return 0xff;
}

int flash_area_get_sectors(int fa_id, uint32_t *count,
                           struct flash_sector *sectors)
{
    const struct flash_area *fa = prv_lookup_flash_area(fa_id);
    if (fa->fa_device_id != FLASH_DEVICE_INTERNAL_FLASH) {
        return -1;
    }

    const size_t sector_size = FLASH_SECTOR_SIZE;
    uint32_t total_count = 0;
    for (size_t off = 0; off < fa->fa_size; off += sector_size) {
        // Note: Offset here is relative to flash area, not device
        sectors[total_count].fs_off = off;
        sectors[total_count].fs_size = sector_size;
        total_count++;
    }

    *count = total_count;
    return 0;
}

int flash_area_id_from_multi_image_slot(int image_index, int slot)
{
    MCUBOOT_LOG_DBG("%s", __func__);
    switch (slot) {
      case 0:
        return FLASH_AREA_IMAGE_PRIMARY(image_index);
      case 1:
        return FLASH_AREA_IMAGE_SECONDARY(image_index);
    }

    MCUBOOT_LOG_ERR("Unexpected Request: image_index=%d, slot=%d", image_index, slot);
    return -1; /* flash_area_open will fail on that */
}

int flash_area_id_from_image_slot(int slot)
{
    return flash_area_id_from_multi_image_slot(0, slot);
}

int flash_area_to_sectors(int idx, int *cnt, struct flash_area *fa)
{
    return -1;
}

void mcuboot_assert_handler(const char *file, int line, const char *func)
{
    ets_printf("assertion failed: file \"%s\", line %d, func: %s\n", file, line, func);
    abort();
}
