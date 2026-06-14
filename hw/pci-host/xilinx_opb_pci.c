/*
 * Xilinx XPS PCI v1.02a host bridge for r1mx-virtex4
 *
 * Models the Xilinx "XPS PCI" IP core (pci_v1_02_a) as used in the RED ONE MX
 * Virtex-4 design.  The core wraps a V3 Semiconductor PCI bridge (ABC/EPC
 * family) and exposes it via the OPB/PLB bus at 0xe1200000.
 *
 * Register layout (from drivers/pci_v1_02_a/src/xpci_l.h + xipif_v1_23_b.h):
 *
 *   IPIF block (standard across all Xilinx IPIF v1.23b devices):
 *     +0x000  DISR   Device Interrupt Status
 *     +0x004  DIPR   Device Interrupt Pending
 *     +0x008  DIER   Device Interrupt Enable
 *     +0x018  DIIR   Device Interrupt ID
 *     +0x01C  DGIER  Device Global Interrupt Enable
 *     +0x020  IISR   IP Interrupt Status
 *     +0x028  IIER   IP Interrupt Enable
 *     +0x040  RESETR Reset
 *
 *   XPci-specific block:
 *     +0x100  PREOVRD  Prefetch override
 *     +0x104  IAR      Interrupt acknowledge
 *     +0x108  SC_DATA  Special cycle data
 *     +0x10C  CAR      Config Address Register  (write = set address)
 *     +0x110  CDR      Config Data Register     (read  = perform cycle)
 *     +0x114  BUSNO    Bus/subordinate bus numbers
 *     +0x118  STATCMD  PCI status+command
 *     +0x11C  STATV3   V3 core transaction status
 *     +0x120  INHIBIT  Transfer inhibit
 *     +0x124  LMADDR   Local bus master address
 *     +0x128  LMA_R    LBM read error address
 *     +0x12C  LMA_W    LBM write error address
 *     +0x130  SERR_R   PCI initiator read SERR address
 *     +0x134  SERR_W   PCI initiator write SERR address
 *     +0x138  PIADDR   PCI address definition
 *     +0x13C  PIA_R    PCI read error address
 *     +0x140  PIA_W    PCI write error address
 *     +0x180..+0x194  IPIF2PCI[0..5]  BAR translations
 *     +0x198  HBDN     Host bridge device number
 *
 * Config cycle addressing (CAR format, standard PCI type-1):
 *   bit 31     : enable
 *   bits[23:16]: bus number
 *   bits[15:11]: device number
 *   bits[10:8] : function number
 *   bits[7:2]  : register offset (dword-aligned)
 *
 * This implementation:
 *   - Accepts all IPIF register reads/writes without side-effects
 *     (firmware just clears/disables interrupts during init)
 *   - Implements CAR/CDR config cycles; bus is empty — all reads return
 *     0xFFFFFFFF (PCI "device not present"), except bus=0/dev=0/fn=0 which
 *     returns the V3 Semiconductor bridge header so VxWorks doesn't abort
 *   - XPci_SelfTest() has no hardware access and always returns XST_SUCCESS,
 *     so no special handling is needed for the self-test path
 *
 * Copyright (c) 2026 r1mx reverse engineering project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "qemu/log.h"
#include "exec/address-spaces.h"

/* -------------------------------------------------------------------------
 * Register indices (offset / 4)
 * ---------------------------------------------------------------------- */
#define R_DISR      (0x000 / 4)
#define R_DIPR      (0x004 / 4)
#define R_DIER      (0x008 / 4)
#define R_DIIR      (0x018 / 4)
#define R_DGIER     (0x01C / 4)
#define R_IISR      (0x020 / 4)
#define R_IIER      (0x028 / 4)
#define R_RESETR    (0x040 / 4)
#define R_PREOVRD   (0x100 / 4)
#define R_IAR       (0x104 / 4)
#define R_SC_DATA   (0x108 / 4)
#define R_CAR       (0x10C / 4)
#define R_CDR       (0x110 / 4)
#define R_BUSNO     (0x114 / 4)
#define R_STATCMD   (0x118 / 4)
#define R_STATV3    (0x11C / 4)
#define R_INHIBIT   (0x120 / 4)
#define R_LMADDR    (0x124 / 4)
#define R_LMA_R     (0x128 / 4)
#define R_LMA_W     (0x12C / 4)
#define R_SERR_R    (0x130 / 4)
#define R_SERR_W    (0x134 / 4)
#define R_PIADDR    (0x138 / 4)
#define R_PIA_R     (0x13C / 4)
#define R_PIA_W     (0x140 / 4)
#define R_HBDN      (0x198 / 4)
#define R_MAX       (0x200 / 4)   /* 512 bytes total register space */

/* -------------------------------------------------------------------------
 * V3 Semiconductor / Xilinx bridge PCI config header (bus 0, dev 0, fn 0)
 *
 * Vendor 0x10EE = Xilinx; device 0x0007 = XPS PCI (matches what some Xilinx
 * reference designs report).  Class 0x0600 = host bridge.
 * ---------------------------------------------------------------------- */
static const uint32_t bridge_cfg[64] = {
    [0x00/4] = 0x000710EE,   /* vendor=Xilinx(0x10EE), device=0x0007        */
    [0x04/4] = 0x00000006,   /* command=0, status=0                          */
    [0x08/4] = 0x06000001,   /* class=host bridge(0x0600), rev 1             */
    [0x0C/4] = 0x00000000,   /* cache line, lat timer, hdr type 0            */
    /* BARs 0x10..0x24: zero (not decoded) */
    [0x2C/4] = 0x000010EE,   /* subsystem vendor=Xilinx, subsystem=0         */
    [0x3C/4] = 0x00000100,   /* max_lat=0, min_gnt=0, irq_pin=INTA, irq=0   */
};

/* -------------------------------------------------------------------------
 * Philips ISP1562 USB host controller (PCI leaf devices)
 *
 * The Build-32 cold-boot device enumerator (FUN_00367f54, reached lazily from
 * the usrRoot device-init cascade) scans PCI config for USB host controllers
 * and BREAKS on the first empty slot; finding none leaves the device count
 * (.data 0xE26978) at 0, so FUN_00563B58 builds no device contexts and the
 * keystone allocator FUN_005651E8/0x5652D0 returns -7.  See
 * firmware/reverse/build_32/boot_reconstruction_status.md ("ROOT CAUSE
 * LOCALIZED", 2026-06-13) and plans/qemu_xilinx_drivers.md Phase 2.
 *
 * The enumerator runs two scans: loop 1 matches 24-bit class 0x0C03A0, loop 2
 * matches 0x0C0320 (USB EHCI).  We expose two single-function devices so both
 * loops find a controller:
 *     bus 0 / dev 1 / fn 0  -> class 0x0C03A0  (no BAR probe in loop 1)
 *     bus 0 / dev 2 / fn 0  -> class 0x0C0320  (loop 2 enables + reads BAR0)
 *
 * Loop 2 enables the device (cmd |= Mem|BusMaster), reads BAR0, then reads the
 * device register at BAR0+offset+8; only if (read>>8)&0xff > 0x40 does it issue
 * a reset and poll.  We back BAR0 with a register block that reads as 0, so the
 * (>>8)&0xff test is 0 and the reset/poll path is skipped.
 *
 * Config dword layout matches the firmware read path (CDR returns the 32-bit
 * word; FUN_00000b3c does (cfg[0x08]>>8) == class).  VID/DID 0x04CC:0x1562.
 * ---------------------------------------------------------------------- */
#define ISP_BAR0_BASE   0xA0000000u   /* in PCI memory window 0 (pci-mem0) */
#define ISP_BAR0_SIZE   0x1000u

#define ISP_DEV_A       1u            /* class 0x0C03A0 (loop 1)            */
#define ISP_DEV_B       2u            /* class 0x0C0320 (loop 2, has BAR0)  */

static const uint32_t isp1562_cfg_a[64] = {
    [0x00/4] = 0x156204CC,   /* device=0x1562, vendor=0x04CC (Philips)      */
    [0x04/4] = 0x02B00000,   /* status (DEVSEL medium), command=0           */
    [0x08/4] = 0x0C03A001,   /* class 0x0C03A0 (USB host), rev 1            */
    [0x0C/4] = 0x00000000,   /* hdr type 0, single function                 */
    [0x2C/4] = 0x156204CC,   /* subsystem id/vendor                         */
    [0x3C/4] = 0x00000100,   /* irq_pin=INTA                                */
};

static const uint32_t isp1562_cfg_b[64] = {
    [0x00/4] = 0x156204CC,   /* device=0x1562, vendor=0x04CC (Philips)      */
    [0x04/4] = 0x02B00000,   /* status (DEVSEL medium), command=0           */
    [0x08/4] = 0x0C032001,   /* class 0x0C0320 (USB EHCI), rev 1            */
    [0x0C/4] = 0x00000000,   /* hdr type 0, single function                 */
    [0x10/4] = ISP_BAR0_BASE,/* BAR0: 32-bit memory at 0xA0000000           */
    [0x2C/4] = 0x156204CC,   /* subsystem id/vendor                         */
    [0x3C/4] = 0x00000100,   /* irq_pin=INTA                                */
};

/* -------------------------------------------------------------------------
 * Device type
 * ---------------------------------------------------------------------- */
#define TYPE_XILINX_OPB_PCI  "xlnx.opb-pci-host"
OBJECT_DECLARE_SIMPLE_TYPE(XilinxOpbPciState, XILINX_OPB_PCI)

struct XilinxOpbPciState {
    SysBusDevice  parent_obj;
    MemoryRegion  mmio;
    MemoryRegion  isp_bar0;       /* ISP1562 dev B BAR0 register block */
    uint32_t      regs[R_MAX];
    uint16_t      isp_a_cmd;      /* shadow of dev A PCI command reg   */
    uint16_t      isp_b_cmd;      /* shadow of dev B PCI command reg   */
};

/* -------------------------------------------------------------------------
 * Config cycle decode
 * ---------------------------------------------------------------------- */
static uint32_t opb_pci_config_read(XilinxOpbPciState *s)
{
    uint32_t car = s->regs[R_CAR];

    /* bit 31 must be set for a valid config cycle */
    if (!(car & 0x80000000U)) {
        return 0xFFFFFFFFU;
    }

    unsigned bus  = (car >> 16) & 0xFF;
    unsigned dev  = (car >> 11) & 0x1F;
    unsigned fn   = (car >>  8) & 0x07;
    unsigned reg  = (car & 0xFC) >> 2;   /* dword index */

    if (bus != 0 || fn != 0) {
        return 0xFFFFFFFFU;          /* only bus 0, function 0 populated */
    }

    /* Host bridge itself: bus 0, device 0, function 0 */
    if (dev == 0) {
        return reg < ARRAY_SIZE(bridge_cfg) ? bridge_cfg[reg] : 0x00000000U;
    }

    /* ISP1562 USB host controllers (see notes above) */
    if (dev == ISP_DEV_A && reg < ARRAY_SIZE(isp1562_cfg_a)) {
        uint32_t v = isp1562_cfg_a[reg];
        if (reg == 0x04/4) {
            v = (v & 0xFFFF0000U) | s->isp_a_cmd;   /* live command reg */
        }
        return v;
    }
    if (dev == ISP_DEV_B && reg < ARRAY_SIZE(isp1562_cfg_b)) {
        uint32_t v = isp1562_cfg_b[reg];
        if (reg == 0x04/4) {
            v = (v & 0xFFFF0000U) | s->isp_b_cmd;   /* live command reg */
        }
        return v;
    }

    /* Populated device, register beyond table, or empty slot */
    if (dev == ISP_DEV_A || dev == ISP_DEV_B) {
        return 0x00000000U;
    }
    return 0xFFFFFFFFU;              /* device not present */
}

/* Config write cycle (CDR write).  We only honour the PCI command register so
 * the enumerator's "enable Mem+BusMaster" (cmd |= 6) sticks; BAR writes (size
 * probing) and everything else are ignored — BARs are fixed. */
static void opb_pci_config_write(XilinxOpbPciState *s, uint32_t val)
{
    uint32_t car = s->regs[R_CAR];

    if (!(car & 0x80000000U)) {
        return;
    }
    if (((car >> 16) & 0xFF) != 0 || ((car >> 8) & 0x07) != 0) {
        return;
    }

    unsigned dev = (car >> 11) & 0x1F;
    unsigned reg = (car & 0xFC) >> 2;

    if (reg == 0x04/4) {
        if (dev == ISP_DEV_A) {
            s->isp_a_cmd = (uint16_t)val;
        } else if (dev == ISP_DEV_B) {
            s->isp_b_cmd = (uint16_t)val;
        }
    }
}

/* -------------------------------------------------------------------------
 * MMIO read
 * ---------------------------------------------------------------------- */
static uint64_t opb_pci_read(void *opaque, hwaddr offset, unsigned size)
{
    XilinxOpbPciState *s = opaque;
    unsigned idx = offset / 4;

    if (idx >= R_MAX) {
        qemu_log_mask(LOG_UNIMP,
                      "xlnx.opb-pci-host: read at +0x%"HWADDR_PRIx"\n",
                      offset);
        return 0;
    }

    if (idx == R_CDR) {
        return opb_pci_config_read(s);
    }

    return s->regs[idx];
}

/* -------------------------------------------------------------------------
 * MMIO write
 * ---------------------------------------------------------------------- */
static void opb_pci_write(void *opaque, hwaddr offset,
                          uint64_t val, unsigned size)
{
    XilinxOpbPciState *s = opaque;
    unsigned idx = offset / 4;

    if (idx >= R_MAX) {
        qemu_log_mask(LOG_UNIMP,
                      "xlnx.opb-pci-host: write 0x%"PRIx64" at +0x%"HWADDR_PRIx"\n",
                      val, offset);
        return;
    }

    /* CDR write: config write cycle */
    if (idx == R_CDR) {
        opb_pci_config_write(s, (uint32_t)val);
        return;
    }

    /* RESETR: IPIF soft reset — clear all registers back to reset state */
    if (idx == R_RESETR && (val & 0x0000000AU)) {
        memset(s->regs, 0, sizeof(s->regs));
        return;
    }

    s->regs[idx] = (uint32_t)val;
}

static const MemoryRegionOps opb_pci_ops = {
    .read       = opb_pci_read,
    .write      = opb_pci_write,
    /* The XPci/V3 bridge registers (CAR/CDR/IPIF) are little-endian on the bus:
     * the firmware accesses them exclusively through byte-swapping accessors
     * (XPci_mReadReg/mWriteReg == FUN_0000010c/FUN_00000118).  Declaring the
     * region little-endian makes the guest's swap + this region's assembly
     * round-trip to the intended register value (CAR enable bit, CDR config
     * data, etc.).  A big-endian region drops the CAR enable bit and breaks
     * every firmware config cycle. */
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

/* -------------------------------------------------------------------------
 * ISP1562 (dev B) BAR0 register block.
 *
 * Reads return 0 so the enumerator's post-match probe — read at BAR0+off+8,
 * test (val>>8)&0xff > 0x40 — evaluates false and the reset/poll path is
 * skipped.  Writes are discarded.  This is a discovery/enumeration stub, not a
 * functional EHCI data path.
 * ---------------------------------------------------------------------- */
static uint64_t isp_bar0_read(void *opaque, hwaddr offset, unsigned size)
{
    return 0;
}

static void isp_bar0_write(void *opaque, hwaddr offset,
                           uint64_t val, unsigned size)
{
}

static const MemoryRegionOps isp_bar0_ops = {
    .read       = isp_bar0_read,
    .write      = isp_bar0_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

/* -------------------------------------------------------------------------
 * Reset
 * ---------------------------------------------------------------------- */
static void opb_pci_reset(DeviceState *dev)
{
    XilinxOpbPciState *s = XILINX_OPB_PCI(dev);
    memset(s->regs, 0, sizeof(s->regs));
    s->isp_a_cmd = 0;
    s->isp_b_cmd = 0;
}

/* -------------------------------------------------------------------------
 * Realize
 * ---------------------------------------------------------------------- */
static void opb_pci_realize(DeviceState *dev, Error **errp)
{
    XilinxOpbPciState *s = XILINX_OPB_PCI(dev);
    memory_region_init_io(&s->mmio, OBJECT(s), &opb_pci_ops, s,
                          TYPE_XILINX_OPB_PCI, 0x10000);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);

    /* ISP1562 dev B BAR0 register block, mapped into PCI memory window 0.
     * Overlap-priority 1 so it wins over the create_unimplemented_device
     * "pci-mem0" catch-all that also covers 0xA0000000. */
    memory_region_init_io(&s->isp_bar0, OBJECT(s), &isp_bar0_ops, s,
                          "isp1562-bar0", ISP_BAR0_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        ISP_BAR0_BASE, &s->isp_bar0, 1);
}

/* -------------------------------------------------------------------------
 * Class + type registration
 * ---------------------------------------------------------------------- */
static void opb_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize     = opb_pci_realize;
    dc->reset       = opb_pci_reset;
    dc->desc        = "Xilinx XPS PCI v1.02a host bridge (OPB)";
}

static const TypeInfo opb_pci_info = {
    .name          = TYPE_XILINX_OPB_PCI,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(XilinxOpbPciState),
    .class_init    = opb_pci_class_init,
};

static void opb_pci_register_types(void)
{
    type_register_static(&opb_pci_info);
}

type_init(opb_pci_register_types)
