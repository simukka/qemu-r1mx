/*
 * NXP PCA9698 — 40-bit Fm+ I2C-bus advanced I/O port expander
 *
 * Models the PCA9698 as found on the RED ONE MX UI board, where it drives the
 * body-mounted status LCD (bit-banged through the expander outputs) and reads
 * the four front-panel buttons.  The Sundance application's
 * "Initializing the status display..." step programs this part over the XPS
 * IIC bus at 7-bit address 0x20; with no slave to ACK, the status-display init
 * spins on XIic_Send forever (the boot never prints
 * "Error initializing the status display", it simply hangs).
 *
 * Datasheet: "PCA9698 40-bit Fm+ I2C-bus advanced I/O port with RESET, OE and
 * INT", Rev. 3 — 3 August 2010.
 *
 *   - 40 I/Os organised in 5 banks of 8 (IO0_x .. IO4_x).
 *   - Command byte: bit7 = AI (auto-increment data pointer), bits6:0 = register
 *     address (datasheet §7.4; power-on default 0x80).
 *   - Register map (per bank, 0..4):
 *        0x00-0x04  IPx   Input Port            (read-only; NAK on write)
 *        0x08-0x0C  OPx   Output Port           (R/W)
 *        0x10-0x14  PIx   Polarity Inversion    (R/W)
 *        0x18-0x1C  IOCx  I/O Configuration     (R/W; 1 = input, default 0xFF)
 *        0x20-0x24  MSKx  Mask Interrupt        (R/W)
 *        0x28       OUTCONF  Output structure   (R/W)
 *        0x29       ALLBNK   Control all banks   (R/W)
 *        0x2A       MODE     Mode selection      (R/W; default 0x02)
 *   - "All I/Os are set to inputs at power-up and RESET."
 *
 * This is a functional model: it ACKs the bus and presents a coherent register
 * file so the firmware's expander writes succeed.  Auto-increment is modelled
 * as a simple linear pointer advance, which matches the consecutive per-bank
 * register layout the firmware walks (e.g. OP0..OP4 at 0x08..0x0C).  The
 * device-ID read-back sequence and the INT/SMBALERT pin are not modelled.
 *
 * Copyright (c) 2026 r1mx reverse engineering project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/i2c/i2c.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "qom/object.h"

#define TYPE_PCA9698 "pca9698"
OBJECT_DECLARE_SIMPLE_TYPE(Pca9698State, PCA9698)

/* Register-file bounds.  Highest defined register is MODE at 0x2A; size the
 * file to the full 7-bit pointer range so auto-increment can never index OOB. */
#define PCA9698_NUM_REGS   0x80

/* Per-bank register group bases (bank index 0..4 added to these). */
#define PCA9698_IP_BASE    0x00   /* Input Port           (read-only) */
#define PCA9698_OP_BASE    0x08   /* Output Port                       */
#define PCA9698_PI_BASE    0x10   /* Polarity Inversion                */
#define PCA9698_IOC_BASE   0x18   /* I/O Configuration                 */
#define PCA9698_MSK_BASE   0x20   /* Mask Interrupt                    */
#define PCA9698_OUTCONF    0x28
#define PCA9698_ALLBNK     0x29
#define PCA9698_MODE       0x2A

#define PCA9698_NUM_BANKS  5

struct Pca9698State {
    I2CSlave parent_obj;

    uint8_t  regs[PCA9698_NUM_REGS];
    uint8_t  ptr;          /* register pointer (7-bit)                       */
    bool     ai;           /* auto-increment flag from the command byte      */
    bool     cmd_pending;  /* next SEND byte after START is the command byte */

    /* Property: idle state of the 40 input lines (buttons released).  Inputs
     * are typically pulled high, so default each bank to 0xFF. */
    uint8_t  input[PCA9698_NUM_BANKS];
};

static bool pca9698_reg_is_input(uint8_t ptr)
{
    /* IPx occupy 0x00..0x04 (PCA9698_IP_BASE is 0). */
    return ptr < PCA9698_IP_BASE + PCA9698_NUM_BANKS;
}

static void pca9698_reset_regs(Pca9698State *s)
{
    int b;

    memset(s->regs, 0, sizeof(s->regs));

    for (b = 0; b < PCA9698_NUM_BANKS; b++) {
        /* Input ports reflect the (released) button / GPIO idle levels. */
        s->regs[PCA9698_IP_BASE + b]  = s->input[b];
        /* All I/Os are inputs at power-up (IOCx = 0xFF). */
        s->regs[PCA9698_IOC_BASE + b] = 0xFF;
        /* Interrupts masked by default. */
        s->regs[PCA9698_MSK_BASE + b] = 0xFF;
    }
    /* MODE default per datasheet Table 11: OCH = 1 -> 0x02. */
    s->regs[PCA9698_MODE] = 0x02;
}

static int pca9698_event(I2CSlave *i2c, enum i2c_event event)
{
    Pca9698State *s = PCA9698(i2c);

    switch (event) {
    case I2C_START_SEND:
        s->cmd_pending = true;   /* next byte is the command byte */
        break;
    case I2C_START_RECV:
        /* Pointer-only read: reuse the pointer set by a preceding write. */
    case I2C_FINISH:
    case I2C_NACK:
    default:
        break;
    }
    return 0;
}

static uint8_t pca9698_recv(I2CSlave *i2c)
{
    Pca9698State *s = PCA9698(i2c);
    uint8_t v;

    /* Keep input-port reads live in case a property/runtime change moved them. */
    if (pca9698_reg_is_input(s->ptr)) {
        s->regs[s->ptr] = s->input[s->ptr - PCA9698_IP_BASE];
    }
    v = s->regs[s->ptr];

    if (s->ai) {
        s->ptr = (s->ptr + 1) & 0x7F;
    }
    return v;
}

static int pca9698_send(I2CSlave *i2c, uint8_t data)
{
    Pca9698State *s = PCA9698(i2c);

    if (s->cmd_pending) {
        s->ptr = data & 0x7F;
        s->ai  = data & 0x80;
        s->cmd_pending = false;
        return 0;
    }

    /* Input Port registers are read-only; hardware NAKs writes to them.  Drop
     * the byte but still ACK so a stray write can't wedge the driver. */
    if (!pca9698_reg_is_input(s->ptr)) {
        s->regs[s->ptr] = data;
    }

    if (s->ai) {
        s->ptr = (s->ptr + 1) & 0x7F;
    }
    return 0;
}

static void pca9698_reset(DeviceState *dev)
{
    Pca9698State *s = PCA9698(dev);

    s->ptr = 0;
    s->ai = false;
    s->cmd_pending = false;
    pca9698_reset_regs(s);
}

static const VMStateDescription vmstate_pca9698 = {
    .name = TYPE_PCA9698,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_I2C_SLAVE(parent_obj, Pca9698State),
        VMSTATE_UINT8_ARRAY(regs, Pca9698State, PCA9698_NUM_REGS),
        VMSTATE_UINT8(ptr, Pca9698State),
        VMSTATE_BOOL(ai, Pca9698State),
        VMSTATE_BOOL(cmd_pending, Pca9698State),
        VMSTATE_UINT8_ARRAY(input, Pca9698State, PCA9698_NUM_BANKS),
        VMSTATE_END_OF_LIST()
    }
};

static Property pca9698_properties[] = {
    /* Idle level of each input bank (1 bit per I/O); default 0xFF (released). */
    DEFINE_PROP_UINT8("input0", Pca9698State, input[0], 0xFF),
    DEFINE_PROP_UINT8("input1", Pca9698State, input[1], 0xFF),
    DEFINE_PROP_UINT8("input2", Pca9698State, input[2], 0xFF),
    DEFINE_PROP_UINT8("input3", Pca9698State, input[3], 0xFF),
    DEFINE_PROP_UINT8("input4", Pca9698State, input[4], 0xFF),
    DEFINE_PROP_END_OF_LIST(),
};

static void pca9698_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *k = I2C_SLAVE_CLASS(klass);

    k->event = pca9698_event;
    k->recv = pca9698_recv;
    k->send = pca9698_send;

    dc->reset = pca9698_reset;
    dc->vmsd = &vmstate_pca9698;
    device_class_set_props(dc, pca9698_properties);
    dc->desc = "NXP PCA9698 40-bit I2C GPIO expander";
}

static const TypeInfo pca9698_info = {
    .name = TYPE_PCA9698,
    .parent = TYPE_I2C_SLAVE,
    .instance_size = sizeof(Pca9698State),
    .class_init = pca9698_class_init,
};

static void pca9698_register_types(void)
{
    type_register_static(&pca9698_info);
}

type_init(pca9698_register_types)
