/*
 * Analog Devices AD9889B HDMI/DVI transmitter — I2C programming-port model
 *
 * Models the AD9889B's 2-wire serial control port (the host-facing SDA/SCL
 * programming interface) as a flat 256-byte register file with an
 * auto-incrementing pointer, which is exactly the protocol the RED firmware's
 * HDMI driver uses: write the register pointer, (repeated-)start, then read.
 *
 * Datasheet: "AD9889 High Performance HDMI/DVI Transmitter", Rev. 0 (10/2005).
 *   - 2-wire programming address = 0x72 (A0 low) or 0x7A (A0 high) [8-bit],
 *     i.e. 7-bit 0x39 or 0x3D  (datasheet p.8, "I2C Addresses").
 *   - R0x00      Chip Revision (read-only, "start from 0").
 *   - R0x96/0x97 interrupt status (write-1-to-clear); masks at R0x94/0x95;
 *     read-only signal state at R0xC5/0xC6 (datasheet p.20, "Interrupts").
 *   - R0x41[6]   power-down; R0x42[7] power-down pin polarity.
 *
 * Goal: make the firmware's `ad9889_interrupt_handler` status reads *succeed*
 * (ACK + return defined values) instead of NAK-looping.  By default no
 * interrupts are pending (R0x96/0x97 = 0) and no sink is connected; set the
 * "hpd" property to advertise a connected monitor.
 *
 * NOTE: this models only the host programming port.  The on-chip I2C masters
 * (HDCP key EEPROM at 0xA0, DDC/EDID at 0xA0) are separate buses on real
 * silicon and are not modelled.
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

#define TYPE_AD9889 "ad9889"
OBJECT_DECLARE_SIMPLE_TYPE(Ad9889State, AD9889)

/* register file indices of interest */
#define AD9889_REG_CHIP_REV   0x00
#define AD9889_REG_PD         0x41   /* [6] power-down                       */
#define AD9889_REG_PD_POL     0x42   /* [7] power-down pin polarity          */
#define AD9889_REG_INT0       0x96   /* interrupt status 0 (write-1-to-clear)*/
#define AD9889_REG_INT1       0x97   /* interrupt status 1                   */
#define AD9889_REG_STATE0     0xC5   /* read-only signal state               */
#define AD9889_REG_STATE1     0xC6
#define AD9889_STATE0_HPD     0x40   /* hot-plug detect (signal state)       */
#define AD9889_STATE0_MSEN    0x20   /* monitor sense                        */

struct Ad9889State {
    I2CSlave parent_obj;

    uint8_t  regs[256];
    uint8_t  ptr;          /* auto-incrementing register pointer */
    bool     ptr_valid;    /* first write of a SEND sets the pointer */

    bool     hpd;          /* property: advertise a connected sink */
};

static void ad9889_reset_regs(Ad9889State *s)
{
    memset(s->regs, 0, sizeof(s->regs));

    /* Chip revision: datasheet default 0 ("start from 0"). */
    s->regs[AD9889_REG_CHIP_REV] = 0x00;

    /* Power-down pin polarity bit reflects the 0x72-address (A0 low) wiring. */
    s->regs[AD9889_REG_PD_POL] = 0x00;

    /* No interrupts pending. */
    s->regs[AD9889_REG_INT0] = 0x00;
    s->regs[AD9889_REG_INT1] = 0x00;

    /* Signal state: optionally advertise a connected/sensed monitor. */
    if (s->hpd) {
        s->regs[AD9889_REG_STATE0] = AD9889_STATE0_HPD | AD9889_STATE0_MSEN;
    }
}

static int ad9889_event(I2CSlave *i2c, enum i2c_event event)
{
    Ad9889State *s = AD9889(i2c);

    switch (event) {
    case I2C_START_SEND:
        s->ptr_valid = false;   /* next byte is the register pointer */
        break;
    case I2C_START_RECV:
    case I2C_FINISH:
    case I2C_NACK:
    default:
        break;
    }
    return 0;
}

static uint8_t ad9889_recv(I2CSlave *i2c)
{
    Ad9889State *s = AD9889(i2c);
    uint8_t v = s->regs[s->ptr];
    s->ptr++;               /* auto-increment, wraps at 256 */
    return v;
}

static int ad9889_send(I2CSlave *i2c, uint8_t data)
{
    Ad9889State *s = AD9889(i2c);

    if (!s->ptr_valid) {
        s->ptr = data;          /* register pointer */
        s->ptr_valid = true;
        return 0;
    }

    switch (s->ptr) {
    case AD9889_REG_CHIP_REV:
    case AD9889_REG_STATE0:
    case AD9889_REG_STATE1:
        /* read-only on hardware; ignore writes */
        break;
    case AD9889_REG_INT0:
    case AD9889_REG_INT1:
        /* write-1-to-clear */
        s->regs[s->ptr] &= ~data;
        break;
    default:
        s->regs[s->ptr] = data;
        break;
    }
    s->ptr++;
    return 0;
}

static void ad9889_reset(DeviceState *dev)
{
    Ad9889State *s = AD9889(dev);

    s->ptr = 0;
    s->ptr_valid = false;
    ad9889_reset_regs(s);
}

static const VMStateDescription vmstate_ad9889 = {
    .name = TYPE_AD9889,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_I2C_SLAVE(parent_obj, Ad9889State),
        VMSTATE_UINT8_ARRAY(regs, Ad9889State, 256),
        VMSTATE_UINT8(ptr, Ad9889State),
        VMSTATE_BOOL(ptr_valid, Ad9889State),
        VMSTATE_END_OF_LIST()
    }
};

static Property ad9889_properties[] = {
    DEFINE_PROP_BOOL("hpd", Ad9889State, hpd, false),
    DEFINE_PROP_END_OF_LIST(),
};

static void ad9889_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *k = I2C_SLAVE_CLASS(klass);

    k->event = ad9889_event;
    k->recv = ad9889_recv;
    k->send = ad9889_send;

    dc->reset = ad9889_reset;
    dc->vmsd = &vmstate_ad9889;
    device_class_set_props(dc, ad9889_properties);
    dc->desc = "Analog Devices AD9889B HDMI transmitter (I2C port)";
}

static const TypeInfo ad9889_info = {
    .name = TYPE_AD9889,
    .parent = TYPE_I2C_SLAVE,
    .instance_size = sizeof(Ad9889State),
    .class_init = ad9889_class_init,
};

static void ad9889_register_types(void)
{
    type_register_static(&ad9889_info);
}

type_init(ad9889_register_types)
