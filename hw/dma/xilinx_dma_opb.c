/*
 * QEMU model of the Xilinx XPS Central DMA (OPB/PLB)
 *
 * Driver source compiled into RED ONE MX firmware (build_32):
 *   dma_v1_10_b: xdma_channel.c, xdma_channel_sg.c, xdma_multi.c, xdma_multi_sg.c
 * Confirmed base address: 0x64010000  (XPAR_DMACHANNEL_0_BASEADDR in xparameters.h)
 *
 * Register map (from dma_v1_10_b/src/xdma_channel_i.h):
 *
 *   +0x00  RST / MI   Reset register (write 0xA to reset) / module info (read)
 *   +0x04  DMAC       DMA Control  — reset value 0x98000000
 *                       bit31 SOURCE_INCR, bit28 DEST_LOCAL, bit27 SG_DISABLE
 *   +0x08  SA         Source Address
 *   +0x0C  DA         Destination Address
 *   +0x10  LEN        Byte count — writing triggers a simple (non-SG) transfer
 *   +0x14  DMAS       DMA Status  — bit31 BUSY
 *   +0x18  BDA        Buffer Descriptor Address (SG mode)
 *   +0x1C  SWCR       Software Control — bit31 SG_ENABLE (write → starts SG chain)
 *   +0x20  UPC        Unserviced Packet Count
 *   +0x24  PCT        Packet Count Threshold
 *   +0x28  PWB        Packet Wait Bound
 *   +0x2C  IS         Interrupt Status  — write-1-to-clear
 *   +0x30  IE         Interrupt Enable
 *
 * Self-test (XDmaChannel_SelfTest in xdma_channel.c):
 *   1. Write XDC_RESET_MASK (0xA) to offset 0x00  → resets channel
 *   2. Read  DMAC at offset 0x04                  → must return 0x98000000
 *   Returns XST_SUCCESS (0) if the value matches, XST_DMA_RESET_REGISTER_ERROR otherwise.
 *
 * Simple transfer (XDmaChannel_Transfer):
 *   Write SA → Write DA → Write LEN (triggers copy from SA to DA in guest RAM)
 *   On done: DMASR BUSY cleared; IS DMA_DONE set; IRQ asserted if IE enables it.
 *
 * SG transfer (XDmaChannel_SgStart / CommitPuts):
 *   BDA holds first descriptor guest-physical address.
 *   Setting SWCR bit31 (SG_ENABLE) starts the chain walk.
 *   Buffer descriptor layout (10 × u32, big-endian in guest RAM):
 *     [0] device_status  [1] control (bit25=last_bd)
 *     [2] src_addr       [3] dst_addr   [4] length
 *     [5] status (HW writes completed length here)
 *     [6] next_ptr (0 = end of chain)   [7-9] reserved
 *
 * Copyright (c) 2026 RED ONE MX reverse-engineering project.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "qom/object.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "exec/address-spaces.h"
#include "hw/ppc/r1mx_activity.h"

/* -------------------------------------------------------------------------
 * Register indices (byte_offset = index << 2)
 * ---------------------------------------------------------------------- */
#define R_RST   0   /* +0x00 reset / module info */
#define R_DMAC  1   /* +0x04 DMA control         */
#define R_SA    2   /* +0x08 source address       */
#define R_DA    3   /* +0x0C destination address  */
#define R_LEN   4   /* +0x10 length               */
#define R_DMAS  5   /* +0x14 DMA status           */
#define R_BDA   6   /* +0x18 buffer descriptor address */
#define R_SWCR  7   /* +0x1C software control     */
#define R_UPC   8   /* +0x20 unserviced pkt count */
#define R_PCT   9   /* +0x24 pkt count threshold  */
#define R_PWB  10   /* +0x28 pkt wait bound       */
#define R_IS   11   /* +0x2C interrupt status     */
#define R_IE   12   /* +0x30 interrupt enable     */
#define R_MAX  13   /* number of *active* XPS-Central-DMA registers (offsets 0x00-0x30) */

/*
 * The device decodes the full 0x10000 PLB slot, not just the 13 Central-DMA
 * registers.  The RED ONE MX IOFPGA packs a separate frame-buffer DMA engine
 * into the same window: its register banks live at +0x4000 (channel A) and
 * +0x8000 (channel B) — e.g. the FrameBufferBlit path drives base 0x64014408
 * with pending/ack at +0x04, control+status at +0x08 and DMACTRL at +0x28
 * (see re_reference / qemu_frmbuf_dma.md).  Those reads/writes previously hit
 * the "out of range" branch (reads → 0, writes dropped), which made the
 * firmware's "FrmBuf: DMA timeout, STAT=0 DMACTRL=0" diagnostic print zeros.
 * Back the whole window so decoded-but-not-yet-modelled registers read back
 * what was written, matching a real IPIF peripheral.  The 13 active registers
 * keep their special behaviour via the switch() below; everything else is
 * plain storage until the frame-buffer DMA is given a proper IRQ-driven model.
 */
#define R_WINDOW (0x10000 >> 2)   /* 64 KB slot / 4 = 16384 word registers */

/* -------------------------------------------------------------------------
 * Bit fields
 * ---------------------------------------------------------------------- */

/* DMAC */
#define DMAC_SOURCE_INCR    (1U << 31)
#define DMAC_DEST_INCR      (1U << 30)
#define DMAC_SOURCE_LOCAL   (1U << 29)
#define DMAC_DEST_LOCAL     (1U << 28)
#define DMAC_SG_DISABLE     (1U << 27)  /* set → simple mode; clear → SG mode */
#define DMAC_RESET_VALUE    0x98000000U /* SOURCE_INCR | DEST_LOCAL | SG_DISABLE */

/* DMAS */
#define DMAS_BUSY           (1U << 31)

/* Software control */
#define SWCR_SG_ENABLE      (1U << 31)

/* IS / IE shared bit masks */
#define IXR_DMA_DONE        (1U << 0)
#define IXR_DMA_ERROR       (1U << 1)
#define IXR_PKT_DONE        (1U << 2)
#define IXR_PKT_THRESHOLD   (1U << 3)
#define IXR_PKT_WAIT_BOUND  (1U << 4)
#define IXR_SG_DISABLE_ACK  (1U << 5)
#define IXR_SG_END          (1U << 6)
#define IXR_BD              (1U << 7)

/* Reset trigger value written to RST register */
#define RST_TRIGGER_MASK    0x0000000AU

/* -------------------------------------------------------------------------
 * Buffer descriptor word indices (each word is 4 bytes, big-endian)
 * ---------------------------------------------------------------------- */
#define BD_DEVICE_STATUS    0
#define BD_CONTROL          1   /* bit25 = XDC_CONTROL_LAST_BD_MASK */
#define BD_SOURCE           2
#define BD_DESTINATION      3
#define BD_LENGTH           4
#define BD_STATUS           5   /* HW writes completed length here */
#define BD_NEXT_PTR         6
#define BD_NWORDS          10   /* 40 bytes per descriptor */

#define BD_CTRL_LAST_BD     (1U << 25)  /* XDC_CONTROL_LAST_BD_MASK */
#define BD_CTRL_GEN_INTR    (1U << 26)  /* XDC_DMACR_GEN_BD_INTR_MASK */

/* Maximum SG chain length to guard against firmware bugs / infinite loops */
#define SG_CHAIN_LIMIT      8192

/* -------------------------------------------------------------------------
 * Device type
 * ---------------------------------------------------------------------- */
#define TYPE_XILINX_OPB_DMA "xlnx.opb-dma-channel"
OBJECT_DECLARE_SIMPLE_TYPE(XilinxOPBDMA, XILINX_OPB_DMA)

struct XilinxOPBDMA {
    SysBusDevice   parent_obj;
    MemoryRegion   mmio;
    qemu_irq       irq;
    uint32_t       regs[R_WINDOW];
    /* Activity monitoring — set by xlnx_opb_dma_set_activity() */
    R1mxActivityCb activity_cb;    /* NULL = disabled */
    void          *activity_opaque;
    uint8_t        dev_id;         /* R1MX_DEV_DMA */
    uint32_t       base_addr;      /* guest physical base address */
};

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static void opb_dma_update_irq(XilinxOPBDMA *s)
{
    qemu_set_irq(s->irq, !!(s->regs[R_IS] & s->regs[R_IE]));
}

static void opb_dma_do_reset(XilinxOPBDMA *s)
{
    memset(s->regs, 0, sizeof(s->regs));
    s->regs[R_DMAC] = DMAC_RESET_VALUE;
    /* IRQ line is de-asserted: IS=0, IE=0 → IS&IE=0 */
    opb_dma_update_irq(s);
}

/*
 * Execute a simple (non-SG) memory-to-memory transfer.
 * Called when LEN is written while DMAC SG_DISABLE is set (default state).
 */
static void opb_dma_do_transfer(XilinxOPBDMA *s)
{
    uint32_t sa  = s->regs[R_SA];
    uint32_t da  = s->regs[R_DA];
    uint32_t len = s->regs[R_LEN];

    if (!len) {
        return;
    }

    s->regs[R_DMAS] |= DMAS_BUSY;

    if (sa && da) {
        /*
         * The firmware only ever DMA-copies between physical RAM regions.
         * g_malloc the intermediate buffer so we can use the AS read/write API
         * without worrying about source and destination aliasing.
         */
        uint8_t *buf = g_try_malloc(len);
        if (buf) {
            address_space_read(&address_space_memory, sa,
                               MEMTXATTRS_UNSPECIFIED, buf, len);
            address_space_write(&address_space_memory, da,
                                MEMTXATTRS_UNSPECIFIED, buf, len);
            g_free(buf);
        } else {
            /*
             * Very large transfer and malloc failed. Set error status so the
             * firmware does not hang waiting for DMA_DONE; it will see an
             * error and recover or abort.
             */
            qemu_log_mask(LOG_GUEST_ERROR,
                          "xlnx.opb-dma: transfer of %u bytes: alloc failed, "
                          "flagging DMA error\n", len);
            s->regs[R_DMAS] &= ~DMAS_BUSY;
            s->regs[R_IS]   |= IXR_DMA_ERROR;
            opb_dma_update_irq(s);
            return;
        }
    }

    s->regs[R_DMAS] &= ~DMAS_BUSY;
    s->regs[R_IS]   |= IXR_DMA_DONE;
    opb_dma_update_irq(s);
}

/*
 * Execute a scatter-gather transfer chain.
 * Called when SWCR SG_ENABLE bit is written.  The BDA register already holds
 * the guest-physical address of the first buffer descriptor.
 *
 * Descriptor format (10 × u32, stored big-endian in guest RAM):
 *   [0] device_status (ignored by us)
 *   [1] control       (bit25 = last BD in packet)
 *   [2] source address
 *   [3] destination address
 *   [4] byte count
 *   [5] status        (we write completed length back here)
 *   [6] next pointer  (guest physical address of next BD; 0 = end)
 *   [7-9] reserved / id / flags
 */
static void opb_dma_do_sg(XilinxOPBDMA *s)
{
    uint32_t bda   = s->regs[R_BDA];
    int      guard = SG_CHAIN_LIMIT;

    if (!bda) {
        /* No descriptor loaded — raise SG_END and done */
        s->regs[R_IS] |= IXR_SG_END | IXR_DMA_DONE;
        s->regs[R_SWCR] &= ~SWCR_SG_ENABLE;
        opb_dma_update_irq(s);
        return;
    }

    s->regs[R_DMAS] |= DMAS_BUSY;

    while (bda && guard-- > 0) {
        uint32_t desc[BD_NWORDS];
        uint32_t src, dst, len, ctrl, next;

        /*
         * Read the descriptor from guest RAM.
         * The PPC firmware is big-endian; each u32 in the descriptor is
         * stored big-endian, so we must byte-swap after reading raw bytes.
         */
        address_space_read(&address_space_memory, bda,
                           MEMTXATTRS_UNSPECIFIED,
                           desc, BD_NWORDS * sizeof(uint32_t));

        ctrl = be32_to_cpu(desc[BD_CONTROL]);
        src  = be32_to_cpu(desc[BD_SOURCE]);
        dst  = be32_to_cpu(desc[BD_DESTINATION]);
        len  = be32_to_cpu(desc[BD_LENGTH]);
        next = be32_to_cpu(desc[BD_NEXT_PTR]);

        /* Transfer this descriptor's buffer */
        if (len && src && dst) {
            uint8_t *buf = g_try_malloc(len);
            if (buf) {
                address_space_read(&address_space_memory, src,
                                   MEMTXATTRS_UNSPECIFIED, buf, len);
                address_space_write(&address_space_memory, dst,
                                    MEMTXATTRS_UNSPECIFIED, buf, len);
                g_free(buf);
            } else {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "xlnx.opb-dma: SG descriptor %u bytes: "
                              "alloc failed\n", len);
                s->regs[R_DMAS] &= ~DMAS_BUSY;
                s->regs[R_IS]   |= IXR_DMA_ERROR;
                s->regs[R_SWCR] &= ~SWCR_SG_ENABLE;
                opb_dma_update_irq(s);
                return;
            }
        }

        /* Write completed length into descriptor BD_STATUS field */
        {
            uint32_t done_len = cpu_to_be32(len);
            address_space_write(&address_space_memory,
                                bda + BD_STATUS * sizeof(uint32_t),
                                MEMTXATTRS_UNSPECIFIED,
                                &done_len, sizeof(uint32_t));
        }

        /* Per-BD interrupt if the GEN_BD_INTR bit is set in DMAC */
        if (s->regs[R_DMAC] & BD_CTRL_GEN_INTR) {
            s->regs[R_IS] |= IXR_BD;
        }

        /* Update BDA to track the current descriptor */
        s->regs[R_BDA] = bda;

        if (ctrl & BD_CTRL_LAST_BD) {
            /* Last BD in this packet — bump unserviced packet count */
            s->regs[R_UPC]++;
            s->regs[R_IS] |= IXR_PKT_DONE;
            if (s->regs[R_UPC] >= (s->regs[R_PCT] & 0xFF)) {
                s->regs[R_IS] |= IXR_PKT_THRESHOLD;
            }
            /* After the last BD the SG engine stops until re-started */
            break;
        }

        if (!next) {
            /* Chain terminated by null next pointer (end of list) */
            s->regs[R_IS] |= IXR_SG_END;
            break;
        }

        bda = next;
    }

    if (guard <= 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "xlnx.opb-dma: SG chain exceeded %d descriptors, "
                      "aborting\n", SG_CHAIN_LIMIT);
    }

    s->regs[R_DMAS] &= ~DMAS_BUSY;
    s->regs[R_IS]   |= IXR_DMA_DONE;

    /* Hardware clears SG_ENABLE after the chain completes */
    s->regs[R_SWCR] &= ~SWCR_SG_ENABLE;

    opb_dma_update_irq(s);
}

/* -------------------------------------------------------------------------
 * MMIO read / write
 * ---------------------------------------------------------------------- */

static uint64_t opb_dma_read(void *opaque, hwaddr offset, unsigned size)
{
    XilinxOPBDMA *s   = opaque;
    unsigned      idx = offset >> 2;
    uint64_t      val;

    if (idx >= R_WINDOW) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "xlnx.opb-dma: read at 0x%"HWADDR_PRIx" out of range\n",
                      offset);
        return 0;
    }

    /* idx >= R_MAX: frame-buffer DMA / other IOFPGA register banks — plain
     * read-back storage (see the R_WINDOW note above). */
    val = s->regs[idx];
    if (s->activity_cb) {
        s->activity_cb(s->dev_id, R1MX_DIR_READ,
                        s->base_addr + (uint32_t)offset, val, size,
                        s->activity_opaque);
    }
    return val;
}

static void opb_dma_write(void *opaque, hwaddr offset,
                          uint64_t val, unsigned size)
{
    XilinxOPBDMA *s   = opaque;
    unsigned      idx = offset >> 2;
    uint32_t      v   = (uint32_t)val;

    if (idx >= R_WINDOW) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "xlnx.opb-dma: write 0x%08x at 0x%"HWADDR_PRIx
                      " out of range\n", v, offset);
        return;
    }

    if (s->activity_cb) {
        s->activity_cb(s->dev_id, R1MX_DIR_WRITE,
                        s->base_addr + (uint32_t)offset, val, size,
                        s->activity_opaque);
    }

    switch (idx) {

    case R_RST:
        /*
         * Writing XDC_RESET_MASK (0xA) to this register triggers a channel
         * reset.  The mask is self-clearing in the hardware; reading back
         * RST after reset returns the Module Info value (don't-care for us).
         * We match any write that has the trigger bits set.
         */
        if (v & RST_TRIGGER_MASK) {
            opb_dma_do_reset(s);
        }
        break;

    case R_IS:
        /*
         * Interrupt Status is write-1-to-clear.  Each bit set in the written
         * value is cleared in IS.
         */
        s->regs[R_IS] &= ~v;
        opb_dma_update_irq(s);
        break;

    case R_IE:
        s->regs[R_IE] = v;
        opb_dma_update_irq(s);
        break;

    case R_LEN:
        /*
         * Writing LEN always triggers a simple (non-SG) memory-to-memory
         * transfer using the current SA and DA registers.
         *
         * Both XDmaChannel_Transfer() (dma_v1_10_b) and XDmaCentral_Transfer()
         * (dmacentral_v1_10_b) trigger the transfer by writing LEN as their
         * final step, regardless of whether DMAC SG_DISABLE is set or clear.
         * The XDmaCentral_SelfTest() explicitly clears SG_DISABLE before
         * writing LEN, so we must NOT gate on that bit here.
         *
         * SG mode is an entirely separate path started by SWCR SG_ENABLE.
         */
        s->regs[R_LEN] = v;
        opb_dma_do_transfer(s);
        break;

    case R_SWCR:
        /*
         * Writing SWCR with SG_ENABLE (bit31) set starts the SG chain.
         * XDmaChannel_SgStart() also subsequently clears DMAC SG_DISABLE;
         * that write lands in the R_DMAC case below and is just stored.
         */
        s->regs[R_SWCR] = v;
        if (v & SWCR_SG_ENABLE) {
            opb_dma_do_sg(s);
        }
        break;

    default:
        /* All other registers are plain read/write */
        s->regs[idx] = v;
        break;
    }
}

static const MemoryRegionOps opb_dma_ops = {
    .read       = opb_dma_read,
    .write      = opb_dma_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        /*
         * The Xilinx IPIF decodes byte/halfword as well as word accesses on the
         * PLB, and the RED frame-buffer DMA driver does issue 16-bit register
         * accesses (lhbrx/sthbrx) to this slot.  Rejecting them (min 4) made
         * QEMU log "Invalid write ... invalid size (min:4 max:4)" and drop the
         * access entirely.  Accept 1/2/4-byte accesses; impl stays at 4 so the
         * memory core assembles sub-word accesses into our 32-bit reg ops
         * (read-modify-write for writes), which the active Central-DMA
         * registers are never touched by sub-word, so no transfer mis-fires.
         */
        .min_access_size = 1,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

/* -------------------------------------------------------------------------
 * DeviceClass callbacks
 * ---------------------------------------------------------------------- */

static void opb_dma_reset_hold(Object *obj)
{
    XilinxOPBDMA *s = XILINX_OPB_DMA(obj);
    opb_dma_do_reset(s);
}

static void opb_dma_realize(DeviceState *dev, Error **errp)
{
    XilinxOPBDMA *s   = XILINX_OPB_DMA(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    memory_region_init_io(&s->mmio, OBJECT(s), &opb_dma_ops, s,
                          TYPE_XILINX_OPB_DMA, 0x10000 /* 64 KB PLB slot */);
    sysbus_init_mmio(sbd, &s->mmio);
    sysbus_init_irq(sbd, &s->irq);
}

static void opb_dma_class_init(ObjectClass *klass, void *data)
{
    DeviceClass    *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    dc->realize      = opb_dma_realize;
    rc->phases.hold  = opb_dma_reset_hold;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo opb_dma_info = {
    .name          = TYPE_XILINX_OPB_DMA,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(XilinxOPBDMA),
    .class_init    = opb_dma_class_init,
};

static void opb_dma_register_types(void)
{
    type_register_static(&opb_dma_info);
}

type_init(opb_dma_register_types)

/* ---------------------------------------------------------------------------
 * Activity monitoring setter — called by r1mx_init() after device creation.
 * --------------------------------------------------------------------------- */
void xlnx_opb_dma_set_activity(DeviceState *dev, uint8_t dev_id,
                                R1mxActivityCb cb, void *opaque)
{
    XilinxOPBDMA *s    = XILINX_OPB_DMA(dev);
    s->dev_id          = dev_id;
    s->activity_cb     = cb;
    s->activity_opaque = opaque;
}

void xlnx_opb_dma_set_base(DeviceState *dev, uint32_t base_addr)
{
    XILINX_OPB_DMA(dev)->base_addr = base_addr;
}
