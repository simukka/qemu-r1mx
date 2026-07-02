/*
 * R1MX device activity reporting interface
 *
 * Provides a shared callback type and per-device constants used by the
 * r1mx-virtex4 machine and its associated device models to route MMIO
 * access events to the activity broker (TCP port 17187).
 *
 * Each device model that participates stores an R1mxActivityCb function
 * pointer and a dev_id in its state struct.  r1mx_init() sets these via the
 * per-device setter functions below.  When the r1mx machine is not in use
 * the callback pointer is left NULL and all calls are no-ops.
 *
 * Copyright (c) 2026 r1mx reverse engineering project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_PPC_R1MX_ACTIVITY_H
#define HW_PPC_R1MX_ACTIVITY_H

#include <stdint.h>
#include "hw/qdev-core.h"

/* -------------------------------------------------------------------------
 * Device IDs — indices into the GUI device list
 * ---------------------------------------------------------------------- */
#define R1MX_DEV_UART        0   /* XPS UARTLite       0xe0600000 */
#define R1MX_DEV_ETHERNET    1   /* XPS EthernetLite   0xe1020000 */
#define R1MX_DEV_DMA         2   /* OPB DMA Channel    0x64010000 */
#define R1MX_DEV_VPFPGA      3   /* VP-FPGA comm FIFO  0xe0080000 (was Luma Histogram) */
#define R1MX_DEV_SDIO        4   /* SD / SDIO block    0xe00a0000 (was RGB Histogram)  */
#define R1MX_DEV_AUDIO       5   /* Audio block        0xe0100000 (was RGB Comp Histo) */
#define R1MX_DEV_IODMA       6   /* IOFPGA DMA block   0xe0120000 (was Mono Histogram) */
#define R1MX_DEV_FRMBUF      7   /* Frame buffer       0xe0200000 (was Luma Waveform)  */
#define R1MX_DEV_FPGA        8   /* FPGA catch-all     0xe0000000 */
#define R1MX_DEV_CPU         9   /* PPC405F6 CPU sampler           */
#define R1MX_DEV_RAM        10   /* System RAM         0x00000000 */
#define R1MX_DEV_ROM        11   /* NOR flash + boot ROM spy       */
#define R1MX_DEV_SDCARD     12   /* Block backend slot 0 (CF/SD)   */
#define R1MX_DEV_SSD        13   /* Block backend slot 1 (SSD)     */

/* -------------------------------------------------------------------------
 * Access direction
 * ---------------------------------------------------------------------- */
#define R1MX_DIR_READ    'R'
#define R1MX_DIR_WRITE   'W'

/* -------------------------------------------------------------------------
 * Callback type
 *
 * dev_id : one of R1MX_DEV_* above
 * dir    : R1MX_DIR_READ or R1MX_DIR_WRITE
 * addr   : guest physical address of the access
 * val    : value read or written (zero for reads that return 0)
 * size   : access width in bytes (1, 2, or 4)
 * opaque : caller-supplied context pointer (the R1mxActivityBroker)
 * ---------------------------------------------------------------------- */
typedef void (*R1mxActivityCb)(uint8_t dev_id, uint8_t dir,
                                uint32_t addr, uint64_t val, unsigned size,
                                void *opaque);

/* -------------------------------------------------------------------------
 * Per-device setter functions — defined in the respective device .c files,
 * called by r1mx_init() after device realisation.
 *
 * Setting cb=NULL disables reporting (default state).
 * ---------------------------------------------------------------------- */

/* hw/misc/red_histogram_ip.c */
void red_histogram_ip_set_activity(DeviceState *dev, uint8_t dev_id,
                                    R1mxActivityCb cb, void *opaque);
void red_histogram_ip_set_base(DeviceState *dev, uint32_t base_addr);

/* hw/dma/xilinx_dma_opb.c */
void xlnx_opb_dma_set_activity(DeviceState *dev, uint8_t dev_id,
                                R1mxActivityCb cb, void *opaque);
void xlnx_opb_dma_set_base(DeviceState *dev, uint32_t base_addr);

#endif /* HW_PPC_R1MX_ACTIVITY_H */
