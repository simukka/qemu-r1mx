/*
 * Xilinx XPS IIC (I2C) controller — "xlnx.xps-iic"
 *
 * Models the LogiCORE IP "XPS IIC Bus Interface" master well enough to drive
 * the firmware's exact Xilinx driver (iic_v1_13_b: xiic_l.c).  Both the FIFO
 * master path (XIic_Recv / XIic_Send) and the dynamic-controller path
 * (XIic_DynRecv / XIic_DynSend) are implemented, because the RED firmware's
 * HDMI/ad9889 access path polls the controller from inside an ISR.
 *
 * Register layout (from iic_v1_13_b/src/xiic_l.h):
 *   IPIF interrupt block (32-bit):
 *     0x1C DGIER   global interrupt enable (bit31)
 *     0x20 IISR    interrupt status        (write-1-to-clear)
 *     0x28 IIER    interrupt enable
 *     0x40 RESETR  soft reset (write 0x0A)
 *   IIC core block (8-bit registers, accessed at the LSB byte lane, +3):
 *     0x100 CR     control      0x104 SR   status
 *     0x108 DTR    tx data      0x10C DRR  rx data
 *     0x110 ADR    slave addr   0x114 TFO  tx FIFO occupancy
 *     0x118 RFO    rx FIFO occ  0x11C TBA  10-bit addr
 *     0x120 RFD    rx FIFO depth 0x124 GPO general output
 *
 * The driver issues the core registers as XIo_Out8(base + reg + 3) and the
 * dynamic data writes as XIo_Out16(base + 0x108 + 2).  We decode by aligning
 * the offset to its 32-bit word (offset & ~3) and distinguish a dynamic DTR
 * write (size 2, carries the DYN_START/DYN_STOP bits in bit8/bit9) from a FIFO
 * DTR write (size 1).
 *
 * The I2C address selection of the downstream devices is NOT modelled here;
 * unmatched (NAK'd) start conditions are logged at LOG_GUEST_ERROR so the real
 * slave addresses surface on the first boot that exercises this controller.
 *
 * Copyright (c) 2026 r1mx reverse engineering project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/i2c/i2c.h"
#include "migration/vmstate.h"
#include "qom/object.h"

/* ---- IPIF interrupt block ---- */
#define R_DGIER     0x1C
#define R_IISR      0x20
#define R_IIER      0x28
#define R_RESETR    0x40
#define RESET_MAGIC 0x0A

/* ---- IIC core block (word-aligned bases; driver pokes the +3 byte lane) ---- */
#define R_CR        0x100
#define R_SR        0x104
#define R_DTR       0x108
#define R_DRR       0x10C
#define R_ADR       0x110
#define R_TFO       0x114
#define R_RFO       0x118
#define R_TBA       0x11C
#define R_RFD       0x120
#define R_GPO       0x124

/* CR bits */
#define CR_EN       0x01    /* device enable           */
#define CR_TXFIFO_RST 0x02
#define CR_MSMS     0x04    /* master start            */
#define CR_DIR_TX   0x08
#define CR_NOACK    0x10
#define CR_RSTA     0x20    /* repeated start          */
#define CR_GC       0x40

/* SR bits */
#define SR_GC          0x01
#define SR_AAS         0x02
#define SR_BUS_BUSY    0x04
#define SR_MSTR_RD     0x08
#define SR_TX_FULL     0x10
#define SR_RX_FULL     0x20
#define SR_RX_EMPTY    0x40
#define SR_TX_EMPTY    0x80

/* IISR / IIER bits */
#define INT_ARB_LOST   0x01
#define INT_TX_ERROR   0x02   /* msg complete / NAK    */
#define INT_TX_EMPTY   0x04
#define INT_RX_FULL    0x08
#define INT_BNB        0x10   /* bus not busy          */
#define INT_AAS        0x20
#define INT_NAAS       0x40
#define INT_TX_HALF    0x80

/* dynamic-mode flags carried in the 16-bit DTR write */
#define DYN_START      0x0100
#define DYN_STOP       0x0200

#define DGIER_GIE      0x80000000u

#define TYPE_XLNX_XPS_IIC "xlnx.xps-iic"
OBJECT_DECLARE_SIMPLE_TYPE(XlnxXpsIicState, XLNX_XPS_IIC)

struct XlnxXpsIicState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    I2CBus      *bus;
    qemu_irq     irq;

    /* programmer-visible state */
    uint8_t  cr, adr, rfd, gpo;
    uint32_t iisr, iier, dgier;

    /* transfer engine */
    bool     active;        /* a master transfer is in progress      */
    bool     dir_read;      /* current transfer is a read            */
    bool     dyn_mode;      /* started via the dynamic controller    */
    bool     nak;           /* address was NAK'd (no slave answered) */
    bool     have_rx;       /* rx_data holds a fetched byte (dynamic) */
    uint8_t  rx_data;
    int      dyn_rx_remaining;

    /* FIFO (standard) mode: the driver pre-loads the TX FIFO with
     * [slave-address, data...] *before* setting MSMS, then the controller
     * transmits address-first when the transfer starts.  Model the whole FIFO,
     * not just one byte, or a pre-loaded register offset clobbers the address. */
    uint8_t  tx_fifo[16];   /* XIic TX FIFO is 16 bytes deep */
    int      tx_count;

    /* Standard-mode master-receive Rx FIFO.  The interrupt-driven driver
     * (XIic_MasterRecv/RecvMasterData) sets the Rx FIFO occupancy threshold via
     * RFD, then drains DRR in its RX_FULL ISR; we clock bytes from the slave up
     * to the threshold and raise RX_FULL, modelling the controller throttling
     * the bus at the FIFO depth. */
    uint8_t  rx_fifo[16];   /* XIic Rx FIFO is 16 bytes deep */
    int      rx_count;

    /* Repeated-start armed: the driver set CR_RSTA while master to hold the bus,
     * and the next address written to DTR must reopen the transfer (repeated
     * START) rather than be sent as data.  This is how XIic_MasterRecv chains a
     * register-pointer write into the data read without releasing the bus. */
    bool     rsta_armed;

    /* Deferred STOP: a master transmit clears MSMS and *then* writes the final
     * data byte (SendMasterData arms the stop before the last XIic_mWriteSendByte).
     * Hold the STOP so that last byte is actually transmitted, then close the
     * transfer and raise BNB so the driver's bus-not-busy completion runs. */
    bool     stop_pending;

    /* Deferred interrupt edges: on real silicon a TX FIFO byte takes time to
     * shift onto the wire (TX_EMPTY asserts after the drain), and an Rx byte
     * takes time to clock in (RX_FULL asserts after it arrives).  The
     * interrupt-driven driver feeds/drains the FIFO one byte per ISR and then
     * acknowledges the edge that woke it (XIic_mClearIisr); if we asserted the
     * NEXT edge *synchronously* inside that same ISR's DTR/DRR access, the
     * acknowledge would swallow it and the multi-byte transfer would stall and
     * time out (~1 s).  So defer TX_EMPTY/RX_FULL to a bottom-half that runs
     * after the guest's ISR returns, modelling the FIFO shift latency. */
    QEMUBH  *bh;
    uint32_t deferred_iisr;
};

#define XIIC_RX_FIFO_DEPTH 16

static void xlnx_iic_update_irq(XlnxXpsIicState *s)
{
    bool level = (s->dgier & DGIER_GIE) && (s->iisr & s->iier);
    qemu_set_irq(s->irq, level);
}

/* Bottom-half: a TX-drain / Rx-fill edge has "completed" on the wire — assert
 * the deferred IISR bit(s) now, after the guest's current ISR/MMIO returned. */
static void xlnx_iic_irq_bh(void *opaque)
{
    XlnxXpsIicState *s = opaque;

    s->iisr |= s->deferred_iisr;
    s->deferred_iisr = 0;
    xlnx_iic_update_irq(s);
}

/* Defer asserting an IISR edge (TX_EMPTY/RX_FULL): clear it now (the FIFO
 * momentarily holds/lacks the byte) and schedule the BH to re-assert it after
 * the guest ISR that is feeding/draining the FIFO returns — so the ISR's own
 * XIic_mClearIisr cannot swallow the next byte's completion edge. */
static void xlnx_iic_defer_int(XlnxXpsIicState *s, uint32_t bit)
{
    s->iisr &= ~bit;
    s->deferred_iisr |= bit;
    qemu_bh_schedule(s->bh);
}

static uint8_t xlnx_iic_status(XlnxXpsIicState *s)
{
    uint8_t sr = SR_TX_EMPTY;            /* TX is drained synchronously */
    if (s->have_rx || s->rx_count > 0) {
        sr |= SR_RX_FULL;
    } else {
        sr |= SR_RX_EMPTY;
    }
    if (s->active) {
        sr |= SR_BUS_BUSY;
        if (s->dir_read) {
            sr |= SR_MSTR_RD;
        }
    }
    return sr;
}

/* Fetch the next byte from the addressed slave into the 1-deep rx holding
 * register and raise RX_FULL so the driver's poll loop releases. */
static void xlnx_iic_prefetch(XlnxXpsIicState *s)
{
    s->rx_data = s->nak ? 0xff : i2c_recv(s->bus);
    s->have_rx = true;
    s->iisr |= INT_RX_FULL;
}

/* Standard-mode master receive: clock bytes from the addressed slave into the
 * Rx FIFO up to the RFD occupancy threshold (RFD+1 bytes), then raise RX_FULL.
 * The driver's ISR (RecvMasterData) reads RFO for the count and drains DRR;
 * each DRR read pops a byte and triggers a refill, so the bus is effectively
 * throttled at the FIFO threshold exactly as the hardware does. */
static void xlnx_iic_rx_refill(XlnxXpsIicState *s)
{
    int target = (int)s->rfd + 1;       /* RFD is a zero-based threshold */

    if (target > XIIC_RX_FIFO_DEPTH) {
        target = XIIC_RX_FIFO_DEPTH;
    }
    while (s->active && s->dir_read && s->rx_count < target) {
        s->rx_fifo[s->rx_count++] = s->nak ? 0xff : i2c_recv(s->bus);
    }
    if (s->rx_count > 0) {
        /* Defer RX_FULL: the byte clocks in after the ISR that drained the
         * previous one returns, so its acknowledge can't swallow this edge. */
        xlnx_iic_defer_int(s, INT_RX_FULL);
    } else {
        xlnx_iic_update_irq(s);
    }
}

static void xlnx_iic_stop(XlnxXpsIicState *s)
{
    if (s->active) {
        i2c_end_transfer(s->bus);
    }
    s->active = false;
    s->dyn_mode = false;
    s->nak = false;
    s->rsta_armed = false;
    s->stop_pending = false;
    s->tx_count = 0;            /* drop any stale staged bytes */
    s->dyn_rx_remaining = 0;
    /* leave have_rx intact: a byte prefetched just before STOP is still read */
    s->iisr |= INT_BNB;
    xlnx_iic_update_irq(s);
}

static void xlnx_iic_begin(XlnxXpsIicState *s, uint8_t addr_byte, bool dynamic)
{
    uint8_t addr7 = addr_byte >> 1;
    bool    recv  = addr_byte & 1;

    s->iisr &= ~INT_BNB;
    s->have_rx = false;
    s->active = true;
    s->dir_read = recv;
    s->dyn_mode = dynamic;

    if (i2c_start_transfer(s->bus, addr7, recv)) {
        /* No slave ACK'd: flag a Tx error so the driver's recv/send returns a
         * failure, but still report BUS_BUSY (already via status) so its
         * "wait for bus busy" spin can make progress. */
        s->nak = true;
        s->iisr |= INT_TX_ERROR;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "xlnx-iic: no slave at I2C addr 0x%02x (%s)\n",
                      addr7, recv ? "read" : "write");
        xlnx_iic_update_irq(s);
        return;
    }

    s->nak = false;
    if (recv) {
        if (dynamic) {
            /* Dynamic reads wait for the DYN_STOP write that carries the count. */
        } else {
            /* Standard-mode master receive: start a fresh Rx FIFO and clock in
             * bytes up to the RFD threshold, raising RX_FULL for the ISR. */
            s->rx_count = 0;
            xlnx_iic_rx_refill(s);
        }
    } else {
        s->iisr |= INT_TX_EMPTY;
    }
    xlnx_iic_update_irq(s);
}

/* Start (or repeated-start) a standard-mode transfer from the staged TX FIFO.
 * FIFO[0] is the slave-address byte (7-bit addr in [7:1], R/W in bit 0); any
 * remaining bytes are data to transmit (for a write).  For a read, begin()
 * prefetches the first byte and the data arrives via DRR reads. */
static void xlnx_iic_start_from_fifo(XlnxXpsIicState *s)
{
    int n = s->tx_count;
    uint8_t addr_byte;

    if (n == 0) {
        return;
    }
    addr_byte = s->tx_fifo[0];
    s->tx_count = 0;

    xlnx_iic_begin(s, addr_byte, false);
    if (s->nak) {
        return;
    }
    if (!s->dir_read) {
        for (int i = 1; i < n; i++) {
            if (i2c_send(s->bus, s->tx_fifo[i])) {
                s->iisr |= INT_TX_ERROR;
            }
        }
        s->iisr |= INT_TX_EMPTY;
        xlnx_iic_update_irq(s);
    }
}

static void xlnx_iic_write_cr(XlnxXpsIicState *s, uint8_t cr)
{
    uint8_t old = s->cr;
    s->cr = cr;

    if (!(cr & CR_EN)) {
        if (s->active) {
            xlnx_iic_stop(s);
        }
        s->tx_count = 0;
        return;
    }
    /* Repeated start (RSTA) while master: hold the bus for a chained transfer.
     * If the new address was already staged into the TX FIFO, reopen now;
     * otherwise arm so the next DTR address byte reopens the transfer (the
     * order XIic_MasterRecv uses: write CR|RSTA, then RFD, then the address). */
    if ((cr & CR_RSTA) && s->active) {
        if (s->tx_count > 0) {
            i2c_end_transfer(s->bus);
            s->active = false;
            xlnx_iic_start_from_fifo(s);
        } else {
            s->rsta_armed = true;
        }
    } else if ((cr & CR_MSMS) && !(old & CR_MSMS) && !s->active) {
        /* MSMS 0->1 starts a transfer using the staged FIFO bytes. */
        xlnx_iic_start_from_fifo(s);
    } else if (!(cr & CR_MSMS) && (old & CR_MSMS) && s->active) {
        if (s->dir_read) {
            /* Receive: STOP immediately; buffered Rx bytes remain readable. */
            xlnx_iic_stop(s);
        } else {
            /* Transmit: the driver clears MSMS just before writing the final
             * byte (stop-after-last-byte).  Defer the STOP until that byte is
             * sent, or until any other access shows no byte is coming. */
            s->stop_pending = true;
        }
    }
}

static void xlnx_iic_write_dtr(XlnxXpsIicState *s, uint64_t val, unsigned size)
{
    if (size >= 2) {
        /* dynamic controller write */
        uint16_t v = val & 0xffff;
        uint8_t  low = v & 0xff;

        if (v & DYN_START) {
            if (s->active) {
                /* repeated start: close then reopen */
                i2c_end_transfer(s->bus);
                s->active = false;
            }
            xlnx_iic_begin(s, low, true);
        }
        if (v & DYN_STOP) {
            if (s->active && s->dir_read) {
                s->dyn_rx_remaining = low ? low : 1;
                xlnx_iic_prefetch(s);
            } else if (s->active && !s->dir_read) {
                if (i2c_send(s->bus, low)) {
                    s->iisr |= INT_TX_ERROR;
                }
                xlnx_iic_stop(s);
            }
            return;
        }
        if (!(v & DYN_START) && s->active && !s->dir_read) {
            if (i2c_send(s->bus, low)) {
                s->iisr |= INT_TX_ERROR;
            }
            s->iisr |= INT_TX_EMPTY;
        }
        return;
    }

    /* FIFO-mode byte */
    {
        uint8_t byte = val & 0xff;
        if (s->active && s->stop_pending && !s->dir_read) {
            /* The final transmit byte after a deferred STOP: send it, then
             * close the transfer and raise BNB for the driver's completion. */
            if (i2c_send(s->bus, byte)) {
                s->iisr |= INT_TX_ERROR;
            }
            s->iisr |= INT_TX_EMPTY;
            xlnx_iic_stop(s);
        } else if (s->active && s->rsta_armed) {
            /* Repeated-start address: close the held segment and reopen the
             * transfer to this new address (XIic_MasterRecv chaining a read). */
            s->rsta_armed = false;
            i2c_end_transfer(s->bus);
            s->active = false;
            s->tx_fifo[0] = byte;
            s->tx_count = 1;
            xlnx_iic_start_from_fifo(s);
        } else if (!s->active) {
            /* Stage into the TX FIFO; drained (address-first) when MSMS or a
             * repeated start (RSTA) launches the transfer. */
            if (s->tx_count < (int)sizeof(s->tx_fifo)) {
                s->tx_fifo[s->tx_count++] = byte;
            }
        } else if (!s->dir_read) {
            /* A data byte written to the FIFO mid-transfer (the interrupt-driven
             * ISR feeding the next byte).  Deliver it, but defer TX_EMPTY to the
             * drain BH: the ISR clears TX_EMPTY right after this write, so a
             * synchronous assertion would be swallowed and the repeated-start
             * completion (which waits on the *next* TX_EMPTY) would never fire. */
            if (i2c_send(s->bus, byte)) {
                s->iisr |= INT_TX_ERROR;
            }
            xlnx_iic_defer_int(s, INT_TX_EMPTY);
            xlnx_iic_update_irq(s);
        }
    }
}

static uint8_t xlnx_iic_read_drr(XlnxXpsIicState *s)
{
    uint8_t v;

    if (s->dyn_mode) {
        v = s->have_rx ? s->rx_data : 0xff;
        s->have_rx = false;
        s->iisr &= ~INT_RX_FULL;
        if (s->active && s->dir_read) {
            if (s->dyn_rx_remaining > 0) {
                s->dyn_rx_remaining--;
            }
            if (s->dyn_rx_remaining > 0) {
                xlnx_iic_prefetch(s);
            } else {
                xlnx_iic_stop(s);
            }
        }
        xlnx_iic_update_irq(s);
        return v;
    }

    /* Standard-mode receive: pop the next byte from the Rx FIFO.  A transfer
     * may already have been stopped (the ISR clears MSMS before the final DRR
     * reads), so a buffered byte stays readable; only refill while still
     * active so the bus throttles at the RFD threshold. */
    if (s->rx_count > 0) {
        v = s->rx_fifo[0];
        s->rx_count--;
        memmove(s->rx_fifo, s->rx_fifo + 1, s->rx_count);
    } else {
        v = 0xff;
    }
    s->iisr &= ~INT_RX_FULL;
    if (s->active && s->dir_read) {
        xlnx_iic_rx_refill(s);
    }
    xlnx_iic_update_irq(s);
    return v;
}

static void xlnx_iic_reset_state(XlnxXpsIicState *s)
{
    if (s->active) {
        i2c_end_transfer(s->bus);
    }
    if (s->bh) {
        qemu_bh_cancel(s->bh);
    }
    s->deferred_iisr = 0;
    s->cr = s->adr = s->rfd = s->gpo = 0;
    s->iisr = s->iier = s->dgier = 0;
    s->active = s->dir_read = s->dyn_mode = s->nak = s->have_rx = false;
    s->rsta_armed = false;
    s->stop_pending = false;
    s->tx_count = 0;
    s->rx_count = 0;
    s->dyn_rx_remaining = 0;
    s->rx_data = 0;
}

static uint64_t xlnx_iic_read(void *opaque, hwaddr offset, unsigned size)
{
    XlnxXpsIicState *s = opaque;
    hwaddr reg = offset & ~0x3ULL;

    /* A deferred STOP with no final byte coming (e.g. an address-only write):
     * the driver has moved on to polling status, so close the transfer now. */
    if (s->stop_pending) {
        xlnx_iic_stop(s);
    }

    switch (reg) {
    case R_DGIER:  return s->dgier;
    case R_IISR:   return s->iisr;
    case R_IIER:   return s->iier;
    case R_CR:     return s->cr;
    case R_SR:     return xlnx_iic_status(s);
    case R_DRR:    return xlnx_iic_read_drr(s);
    case R_ADR:    return s->adr;
    case R_TFO:    return 0;                 /* tx FIFO always empty */
    case R_RFO:    /* Rx FIFO occupancy, zero-based (BytesInFifo = RFO + 1). */
                   return s->rx_count > 0 ? s->rx_count - 1 : 0;
    case R_RFD:    return s->rfd;
    case R_GPO:    return s->gpo;
    default:       return 0;
    }
}

static void xlnx_iic_write(void *opaque, hwaddr offset, uint64_t val,
                           unsigned size)
{
    XlnxXpsIicState *s = opaque;
    hwaddr reg = offset & ~0x3ULL;

    /* Resolve a deferred STOP when the next access isn't the final TX byte:
     * a write to DTR may be that byte (handled in write_dtr), anything else
     * means the transmit is already done, so close the transfer now. */
    if (s->stop_pending && reg != R_DTR) {
        xlnx_iic_stop(s);
    }

    switch (reg) {
    case R_RESETR:
        if ((val & 0xff) == RESET_MAGIC) {
            xlnx_iic_reset_state(s);
        }
        break;
    case R_DGIER:  s->dgier = val; xlnx_iic_update_irq(s); break;
    case R_IISR:   s->iisr &= ~(uint32_t)val; xlnx_iic_update_irq(s); break;
    case R_IIER:   s->iier = val; xlnx_iic_update_irq(s); break;
    case R_CR:     xlnx_iic_write_cr(s, val & 0xff); break;
    case R_DTR:    xlnx_iic_write_dtr(s, val, size); break;
    case R_ADR:    s->adr = val & 0xff; break;
    case R_RFD:    s->rfd = val & 0xff; break;
    case R_GPO:    s->gpo = val & 0xff; break;
    default:       break;
    }
}

static const MemoryRegionOps xlnx_iic_ops = {
    .read = xlnx_iic_read,
    .write = xlnx_iic_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
};

static void xlnx_iic_reset(DeviceState *dev)
{
    xlnx_iic_reset_state(XLNX_XPS_IIC(dev));
}

static void xlnx_iic_realize(DeviceState *dev, Error **errp)
{
    XlnxXpsIicState *s = XLNX_XPS_IIC(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    memory_region_init_io(&s->iomem, OBJECT(s), &xlnx_iic_ops, s,
                          TYPE_XLNX_XPS_IIC, 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
    s->bus = i2c_init_bus(dev, "i2c");
    s->bh = qemu_bh_new(xlnx_iic_irq_bh, s);
}

static const VMStateDescription vmstate_xlnx_iic = {
    .name = TYPE_XLNX_XPS_IIC,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT8(cr, XlnxXpsIicState),
        VMSTATE_UINT8(adr, XlnxXpsIicState),
        VMSTATE_UINT8(rfd, XlnxXpsIicState),
        VMSTATE_UINT8(gpo, XlnxXpsIicState),
        VMSTATE_UINT32(iisr, XlnxXpsIicState),
        VMSTATE_UINT32(iier, XlnxXpsIicState),
        VMSTATE_UINT32(dgier, XlnxXpsIicState),
        VMSTATE_BOOL(active, XlnxXpsIicState),
        VMSTATE_BOOL(dir_read, XlnxXpsIicState),
        VMSTATE_BOOL(dyn_mode, XlnxXpsIicState),
        VMSTATE_BOOL(nak, XlnxXpsIicState),
        VMSTATE_BOOL(have_rx, XlnxXpsIicState),
        VMSTATE_UINT8(rx_data, XlnxXpsIicState),
        VMSTATE_INT32(dyn_rx_remaining, XlnxXpsIicState),
        VMSTATE_INT32(tx_count, XlnxXpsIicState),
        VMSTATE_UINT8_ARRAY(tx_fifo, XlnxXpsIicState, 16),
        VMSTATE_INT32(rx_count, XlnxXpsIicState),
        VMSTATE_UINT8_ARRAY(rx_fifo, XlnxXpsIicState, 16),
        VMSTATE_BOOL(rsta_armed, XlnxXpsIicState),
        VMSTATE_BOOL(stop_pending, XlnxXpsIicState),
        VMSTATE_END_OF_LIST()
    }
};

static void xlnx_iic_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = xlnx_iic_realize;
    dc->reset = xlnx_iic_reset;
    dc->vmsd = &vmstate_xlnx_iic;
    dc->desc = "Xilinx XPS IIC controller";
}

static const TypeInfo xlnx_iic_info = {
    .name = TYPE_XLNX_XPS_IIC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(XlnxXpsIicState),
    .class_init = xlnx_iic_class_init,
};

static void xlnx_iic_register_types(void)
{
    type_register_static(&xlnx_iic_info);
}

type_init(xlnx_iic_register_types)
