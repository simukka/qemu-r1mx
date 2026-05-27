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

#define TYPE_RED_HISTOGRAM_IP  "red.histogram-ip"
OBJECT_DECLARE_SIMPLE_TYPE(RedHistogramIPState, RED_HISTOGRAM_IP)

struct RedHistogramIPState {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
};

static uint64_t red_hist_read(void *opaque, hwaddr offset, unsigned size)
{
    /* All reads return 0:
     *   - Status bits (bit 5 at +0x3c) = 0  → firmware skips "enabled" path
     *   - Histogram data registers = 0       → empty histogram buckets
     *   - No IRQ pending bits set            → no spurious interrupts
     */
    return 0;
}

static void red_hist_write(void *opaque, hwaddr offset,
                           uint64_t val, unsigned size)
{
    /* Silently discard all writes.
     * Observed writes: +0x38 ← 0x20 (enable?), +0x3c ← 0x20 (status clear?)
     * Without real sensor data these writes have no useful effect.
     */
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
}

static void red_hist_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = red_hist_realize;
    dc->desc    = "RED ONE MX FPGA histogram/waveform IP stub";
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
