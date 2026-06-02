/*
 * RED ONE MX — Custom FPGA histogram/waveform IP stub
 *
 * Five proprietary RED FPGA IP cores are mapped in the Virtex-4 PLB address
 * space.  Their register layouts are not publicly documented; behavior is
 * inferred from firmware disassembly (Build 32, re_reference §6).
 *
 * Confirmed access patterns (fn_355a08, fn_355b10, fn_355b64):
 *   - Firmware reads offsets +0x34, +0x38, +0x3c within each block during
 *     sysHwInit_seq initialisation.
 *   - All reads are followed by conditional branches (never loop-back) so
 *     returning 0 for all reads is safe — the firmware skips the
 *     "hardware present / enabled" paths and continues boot.
 *   - Writes to +0x38 and +0x3c with value 0x20 are the only observed
 *     side-effects; they are discarded here (no histogram hardware to drive).
 *   - Interrupt outputs are never asserted: histogram-done IRQs require
 *     real sensor data, which is absent in emulation.
 *
 * All five instances share this single type; each is given a 64 KB MMIO
 * region at its PLB base address.
 *
 * Instances in r1mx-virtex4 machine:
 *   "Luma Histogram"   0xe0080000
 *   "RGB Histogram"    0xe00a0000
 *   "RGB Comp Histo"   0xe0100000
 *   "Mono Histogram"   0xe0120000
 *   "Luma Waveform"    0xe0200000
 *
 * Copyright (c) 2026 r1mx reverse engineering project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/ppc/r1mx_activity.h"

#define TYPE_RED_HISTOGRAM_IP  "red.histogram-ip"
OBJECT_DECLARE_SIMPLE_TYPE(RedHistogramIPState, RED_HISTOGRAM_IP)

struct RedHistogramIPState {
    SysBusDevice  parent_obj;
    MemoryRegion  mmio;
    /* Activity monitoring — set by r1mx_init() via red_histogram_ip_set_activity() */
    R1mxActivityCb activity_cb;    /* NULL = disabled */
    void          *activity_opaque;
    uint8_t        dev_id;         /* R1MX_DEV_HIST_* */
    uint32_t       base_addr;      /* guest physical base, filled at realize  */
};

static uint64_t red_hist_read(void *opaque, hwaddr offset, unsigned size)
{
    RedHistogramIPState *s = opaque;
    uint64_t val = 0;
    /* All reads return 0 (see file header for rationale). */
    if (s->activity_cb) {
        s->activity_cb(s->dev_id, R1MX_DIR_READ,
                        s->base_addr + (uint32_t)offset, val, size,
                        s->activity_opaque);
    }
    return val;
}

static void red_hist_write(void *opaque, hwaddr offset,
                           uint64_t val, unsigned size)
{
    RedHistogramIPState *s = opaque;
    /* Silently discard all writes (see file header for rationale). */
    if (s->activity_cb) {
        s->activity_cb(s->dev_id, R1MX_DIR_WRITE,
                        s->base_addr + (uint32_t)offset, val, size,
                        s->activity_opaque);
    }
}

static const MemoryRegionOps red_hist_ops = {
    .read       = red_hist_read,
    .write      = red_hist_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void red_hist_realize(DeviceState *dev, Error **errp)
{
    RedHistogramIPState *s = RED_HISTOGRAM_IP(dev);
    memory_region_init_io(&s->mmio, OBJECT(s), &red_hist_ops, s,
                          TYPE_RED_HISTOGRAM_IP, 0x20000);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);
    /* dev_id defaults to FPGA catch-all until r1mx_init sets a real one */
    s->dev_id = R1MX_DEV_FPGA;
}

static void red_hist_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = red_hist_realize;
    dc->desc    = "RED ONE MX FPGA histogram/waveform IP stub";
}

/*
 * red_histogram_ip_set_activity — called by r1mx_init() after sysbus_mmio_map().
 *
 * base_addr must be the guest physical address that was passed to
 * sysbus_mmio_map() so that offsets within the region can be reported as
 * absolute guest addresses to the activity monitor.
 */
void red_histogram_ip_set_activity(DeviceState *dev, uint8_t dev_id,
                                    R1mxActivityCb cb, void *opaque)
{
    RedHistogramIPState *s = RED_HISTOGRAM_IP(dev);
    s->dev_id          = dev_id;
    s->activity_cb     = cb;
    s->activity_opaque = opaque;
    /* base_addr is set by the separate red_histogram_ip_set_base() call,
     * or we derive it from the mapped mmio region via sysbus internals.
     * For simplicity the caller sets base_addr through the dedicated setter. */
}

void red_histogram_ip_set_base(DeviceState *dev, uint32_t base_addr)
{
    RED_HISTOGRAM_IP(dev)->base_addr = base_addr;
}

static const TypeInfo red_hist_info = {
    .name          = TYPE_RED_HISTOGRAM_IP,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(RedHistogramIPState),
    .class_init    = red_hist_class_init,
};

static void red_hist_register_types(void)
{
    type_register_static(&red_hist_info);
}

type_init(red_hist_register_types)
