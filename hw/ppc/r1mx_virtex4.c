/*
 * RED ONE MX — Xilinx Virtex-4 FX (PPC405F6) machine
 *
 * Models the hardware platform of the RED ONE MX digital cinema camera:
 *   CPU  : PPC405F6 hard-macro embedded in a Xilinx Virtex-4 FX FPGA
 *   MMIO : Xilinx EDK IP cores (XIntc, XUartLite, XEmacLite) at PLB addresses
 *   Goal : boot VxWorks 2.10 firmware far enough to reach the WDB debug agent
 *          on UDP port 17185 via the XEmacLite connected to a host TAP device
 *
 * Design note on SoC choice
 *   We deliberately do NOT use TYPE_PPC405_SOC (ppc405.h) here.  That SoC
 *   model unconditionally claims serial_hd(0) and serial_hd(1) for the
 *   on-chip OPB UART macros during its realize callback, leaving our FPGA
 *   XUartLite with no free chardev to attach to.  Instead we create a bare
 *   PowerPCCPU (same pattern as hw/ppc/virtex_ml507.c for PPC440) and add
 *   only the FPGA-fabric peripherals that the firmware actually uses.
 *   DCR accesses to the absent PPC405 on-chip peripherals return 0 silently.
 *
 * References
 *   Xilinx UG018  — Virtex-4 Embedded Processor Block
 *   Xilinx DS570  — XPS UARTLite IP core
 *   Xilinx DS599  — XPS EthernetLite IP core
 *   Xilinx DS572  — XPS Interrupt Controller IP core
 *   firmware/reverse/build_32/re_reference.md §6 (PLB table), §7 (DCR map)
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "cpu.h"
#include "hw/boards.h"
#include "hw/ppc/ppc.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/misc/unimp.h"
#include "exec/address-spaces.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "net/net.h"
#include "qemu/main-loop.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

/* ---------------------------------------------------------------------------
 * PLB address map (from PLB table at firmware offset 0xdfbbc8, re_reference §6)
 * --------------------------------------------------------------------------- */
#define UARTLITE_BASE   0xe0600000u  /* XPS UARTLite  — 115200 8N1, TX FIFO +4 */
#define UART550_0_BASE  0xe0640000u  /* XPS UART16550 #1 — not modelled        */
#define UART550_1_BASE  0xe0650000u  /* XPS UART16550 #2 — not modelled        */
#define INTC_BASE       0xe0800000u  /* XPS Interrupt Controller               */
#define ERRCTRS_BASE    0xe0be0000u  /* RED custom error-counter IP            */
#define HIST0_BASE      0xe00a0000u  /* RED histogram IP 0                     */
#define HIST1_BASE      0xe0080000u  /* RED histogram IP 1                     */
#define HIST2_BASE      0xe0100000u  /* RED histogram IP 2                     */
#define HIST3_BASE      0xe0120000u  /* RED histogram IP 3                     */
#define HIST4_BASE      0xe0200000u  /* RED histogram IP 4                     */
#define ETHLITE_BASE    0xe1020000u  /* XPS EthernetLite — WDB endpoint        */
#define PCI_CFG_BASE    0xe1200000u  /* XPS PCI v3 config registers            */
#define I2C_BASE        0xb2600000u  /* XPS IIC (I²C)                          */
#define PCI_MEM_BASE    0xa0000000u  /* PCI memory window (64 MB)              */
#define PCI_MEM2_BASE   0x80000000u  /* PCI memory window 2 (512 MB)           */
#define NOR_FLASH_BASE  0xf0000000u  /* NOR flash 128 MB                       */
#define BOOT_ROM_BASE   0xffff0000u  /* Boot ROM 64 KB                         */

/* Unimplemented device region sizes (must be ≥ max register offset + 4) */
/* NS550: XUN_REG_OFFSET = 0x1000; highest reg at 0x101F → need > 0x1020 */
#define UART550_SIZE    0x2000u
#define DMA_BASE        0x64010000u  /* XPS Central DMA — confirmed by xparameters.h */
#define DMA_SIZE        0x10000u     /* 64 KB standard PLB mapping */
#define ERRCTRS_SIZE    0x1000u
#define HIST_SIZE       0x10000u
#define PCI_CFG_SIZE    0x10000u
#define I2C_SIZE        0x1000u
#define PCI_MEM_SIZE    (64  * MiB)
#define PCI_MEM2_SIZE   (512 * MiB)
#define NOR_FLASH_SIZE  (128 * MiB)
#define BOOT_ROM_SIZE   (64  * KiB)

/* XIntc drives 32 interrupt lines; connect peripherals as follows:
 *   irq[0]  — XUartLite
 *   irq[1]  — XEmacLite
 *   irq[2]  — XPS Central DMA (line TBD from real hardware; 2 is a placeholder)
 * All others are left unconnected (silent).
 */
#define IRQ_UARTLITE    0
#define IRQ_ETHLITE     1
#define IRQ_DMA         2

/* ---------------------------------------------------------------------------
 * NOR flash / boot ROM stub
 *
 * The RED ONE MX uses parallel NOR flash at 0xf0000000 (128 MB) accessed via
 * the PPC405 External Bus Controller (EBC).  A 64 KB boot ROM alias appears at
 * 0xffff0000.  The firmware is loaded directly into DRAM in our emulation so
 * we never execute from flash, but VxWorks TFFS (True Flash File System) probes
 * this region during usrRoot() and expects the erased-flash all-ones pattern
 * (0xFF) rather than zeros.  Returning 0x00 causes CFI detection to mis-fire and
 * TFFS to log "flash geometry mismatch" errors that can stall boot.
 *
 * This stub returns 0xFF for all reads and silently discards writes (no
 * persistent backing store — flash programming has no effect in emulation).
 * --------------------------------------------------------------------------- */
static uint64_t nor_flash_read(void *opaque, hwaddr offset, unsigned size)
{
    /* Erased NOR flash: all bits high */
    return 0xFFFFFFFFFFFFFFFFULL >> (64 - size * 8);
}

static void nor_flash_write(void *opaque, hwaddr offset,
                            uint64_t val, unsigned size)
{
    /* Discard: no persistent flash backing in emulation */
}

static const MemoryRegionOps nor_flash_ops = {
    .read       = nor_flash_read,
    .write      = nor_flash_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

/* ---------------------------------------------------------------------------
 * FPGA fabric TCP bridge (port 17186)
 *
 * Every write to an FPGA peripheral (0xe0000000-0xe3ffffff) is forwarded to
 * any connected TCP client as a 16-byte binary record:
 *
 *   bytes  0-3   magic "RFPG"
 *   bytes  4-7   guest physical address (big-endian uint32)
 *   bytes  8-11  value written (big-endian uint32)
 *   byte   12    access size in bytes (1, 2, or 4)
 *   bytes  13-15 reserved (zero)
 *
 * The StatusLCDWidget in toolkit/gui/widgets/status_lcd.py connects to this
 * port and uses RFPG records to track FPGA register writes for display debug.
 * When no client is connected, writes are silently discarded.
 * --------------------------------------------------------------------------- */
#define LCD_TCP_PORT     17186

typedef struct R1mxLcdBridge {
    int  listen_fd;   /* server socket (O_NONBLOCK), -1 if unavailable */
    int  client_fd;   /* accepted client, -1 if disconnected           */
} R1mxLcdBridge;

static R1mxLcdBridge g_lcd_bridge = { .listen_fd = -1, .client_fd = -1 };

/* Called by QEMU event loop when the listening socket has an incoming conn. */
static void lcd_bridge_accept(void *opaque)
{
    R1mxLcdBridge *br = opaque;
    int fd = accept(br->listen_fd, NULL, NULL);
    if (fd < 0) {
        return;
    }
    /* Drop existing client and replace with new one. */
    if (br->client_fd >= 0) {
        close(br->client_fd);
    }
    br->client_fd = fd;
    /* Enable TCP_NODELAY so small packets are sent immediately. */
    {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
}

/* Initialise the listening socket; errors are non-fatal (bridge disabled). */
static void lcd_bridge_init(R1mxLcdBridge *br)
{
    struct sockaddr_in addr;
    int fd, one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(LCD_TCP_PORT);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, 1) < 0) {
        close(fd);
        return;
    }

    br->listen_fd = fd;
    qemu_set_fd_handler(fd, lcd_bridge_accept, NULL, br);
}

/* Send a 16-byte RFPG packet for one MMIO write; drops silently on error. */
static void lcd_bridge_send(R1mxLcdBridge *br,
                            uint32_t addr, uint64_t val, unsigned size)
{
    uint8_t pkt[16];
    if (br->client_fd < 0) {
        return;
    }
    pkt[0] = 'R'; pkt[1] = 'F'; pkt[2] = 'P'; pkt[3] = 'G';
    pkt[4]  = (addr >> 24) & 0xff;
    pkt[5]  = (addr >> 16) & 0xff;
    pkt[6]  = (addr >>  8) & 0xff;
    pkt[7]  =  addr        & 0xff;
    pkt[8]  = (val  >> 24) & 0xff;
    pkt[9]  = (val  >> 16) & 0xff;
    pkt[10] = (val  >>  8) & 0xff;
    pkt[11] =  val         & 0xff;
    pkt[12] = (uint8_t)size;
    pkt[13] = pkt[14] = pkt[15] = 0;

    if (send(br->client_fd, pkt, sizeof(pkt), MSG_NOSIGNAL) < 0) {
        close(br->client_fd);
        br->client_fd = -1;
    }
}

/* ---------------------------------------------------------------------------
 * FPGA fabric catch-all MMIO region (0xe0000000 - 0xe3ffffff, 64 MB)
 *
 * Absorbs accesses to FPGA peripherals not yet individually modelled so that
 * the firmware does not trigger Machine Check Exceptions on those addresses.
 * Reads return 0; writes are forwarded to the LCD TCP bridge.
 * Priority -2000 keeps this region BELOW all named devices mapped in the same
 * address range (XIntc at 0xe0800000, XUartLite at 0xe0600000, etc.).
 * --------------------------------------------------------------------------- */
static uint64_t fpga_catchall_read(void *opaque, hwaddr offset, unsigned size)
{
    (void)opaque; (void)offset; (void)size;
    return 0;
}

static void fpga_catchall_write(void *opaque, hwaddr offset,
                                uint64_t val, unsigned size)
{
    R1mxLcdBridge *br = opaque;
    lcd_bridge_send(br, (uint32_t)(0xe0000000u + offset), val, size);
}

static const MemoryRegionOps fpga_catchall_ops = {
    .read       = fpga_catchall_read,
    .write      = fpga_catchall_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

/* Machine state ----------------------------------------------------------- */

typedef struct R1mxState {
    MachineState    parent;
    /* No embedded SoC: we use a bare PPC405 CPU to avoid serial_hd conflicts
     * from the OPB UARTs inside Ppc405SoCState.  See design note above. */
} R1mxState;

#define TYPE_R1MX_MACHINE   MACHINE_TYPE_NAME("r1mx-virtex4")
DECLARE_INSTANCE_CHECKER(R1mxState, R1MX_MACHINE, TYPE_R1MX_MACHINE)

/* ---------------------------------------------------------------------------
 * Machine initialisation
 * --------------------------------------------------------------------------- */

static void r1mx_init(MachineState *machine)
{
    PowerPCCPU  *cpu;
    CPUPPCState *env;
    MemoryRegion *sysmem = get_system_memory();
    DeviceState *intc_dev;
    SysBusDevice *intc_sbd;
    qemu_irq     intc_irqs[32];
    qemu_irq     cpu_irq;
    int          i;

    /* --- Bare PPC405 CPU ------------------------------------------------- */
    cpu = POWERPC_CPU(cpu_create(machine->cpu_type));
    env = &cpu->env;

    /* Make cpu_reset() restore PVR to the Virtex-4 PPC405F6 value.
     * ppc_cpu_reset_hold() resets ALL SPRs to their default_value, so we
     * patch the default here before the first reset runs. */
    env->spr_cb[SPR_PVR].default_value = 0x20011000;
    env->spr[SPR_PVR]                  = 0x20011000;

    /* PPC405 init_excp_4xx_softmmu sets hreset_vector = 0xFFFFFFFCUL (boot ROM).
     * The RED ONE MX firmware is loaded at physical 0x0, not at the PPC boot ROM.
     * Override hreset_vector so every cpu_reset() lands at 0x0 instead. */
    env->hreset_vector = 0x00000000UL;

    /* PPC405 needs the 40x timer helpers (PIT/FIT/WDT).
     * Do NOT use ppc_booke_timers_init here — that is for PPC440 (Book-E).
     * ppc_40x_timers_init allocates the wdt_timer that store_40x_tcr requires. */
    ppc_40x_timers_init(env, 400000000, PPC_INTERRUPT_PIT);

    /* Register a CPU reset handler — same pattern as ppc440_bamboo.c */
    qemu_register_reset((QEMUResetHandler *)cpu_reset, cpu);

    /* Connect the PPC405 external interrupt to the XIntc below */
    cpu_irq = qdev_get_gpio_in(DEVICE(cpu), PPC40x_INPUT_INT);

    /* --- 256 MB RAM at 0x00000000 ----------------------------------------
     * Allocate directly (not via machine->ram / HostMemoryBackend) so TCG's
     * qemu_ram_addr_from_host() always finds the block in ram_list. */
    {
        MemoryRegion *ram = g_new(MemoryRegion, 1);
        memory_region_init_ram(ram, NULL, "r1mx.ram",
                               machine->ram_size, &error_fatal);
        memory_region_add_subregion(sysmem, 0x0, ram);
    }

    /* --- XPS Interrupt Controller (XIntc) -------------------------------- */
    intc_dev = qdev_new("xlnx.xps-intc");
    qdev_prop_set_uint32(intc_dev, "kind-of-intr", 0);
    intc_sbd = SYS_BUS_DEVICE(intc_dev);
    sysbus_realize_and_unref(intc_sbd, &error_fatal);
    sysbus_mmio_map(intc_sbd, 0, INTC_BASE);
    sysbus_connect_irq(intc_sbd, 0, cpu_irq);

    /* Collect XIntc output lines so peripherals can trigger interrupts. */
    for (i = 0; i < 32; i++) {
        intc_irqs[i] = qdev_get_gpio_in(intc_dev, i);
    }

    /* --- XPS UARTLite (console, 115200 8N1) ------------------------------ */
    {
        DeviceState  *uart_dev = qdev_new("xlnx.xps-uartlite");
        SysBusDevice *uart_sbd = SYS_BUS_DEVICE(uart_dev);
        /* serial_hd(0) is ours — no competing OPB UART when using bare CPU */
        if (serial_hd(0)) {
            qdev_prop_set_chr(uart_dev, "chardev", serial_hd(0));
        }
        sysbus_realize_and_unref(uart_sbd, &error_fatal);
        sysbus_mmio_map(uart_sbd, 0, UARTLITE_BASE);
        sysbus_connect_irq(uart_sbd, 0, intc_irqs[IRQ_UARTLITE]);
    }

    /* --- XPS EthernetLite (WDB UDP 17185) -------------------------------- */
    {
        DeviceState  *eth_dev = qdev_new("xlnx.xps-ethernetlite");
        SysBusDevice *eth_sbd = SYS_BUS_DEVICE(eth_dev);
        qdev_prop_set_uint32(eth_dev, "tx-ping-pong", 1);
        qdev_prop_set_uint32(eth_dev, "rx-ping-pong", 1);
        if (nd_table[0].used) {
            qdev_set_nic_properties(eth_dev, &nd_table[0]);
        }
        sysbus_realize_and_unref(eth_sbd, &error_fatal);
        sysbus_mmio_map(eth_sbd, 0, ETHLITE_BASE);
        sysbus_connect_irq(eth_sbd, 0, intc_irqs[IRQ_ETHLITE]);
    }

    /* --- Unimplemented / stub regions ------------------------------------ */

    /* XPS UART16550 #1 and #2 (not used for debug; firmware probes them)
     * NOTE: XUN_REG_OFFSET = 0x1000 — the NS550 driver accesses registers
     * starting at base+0x1000 (RBR at +0x1003, highest at +0x101F).
     * UART550_SIZE must be > 0x1020 to avoid MCE on those accesses. */
    create_unimplemented_device("uart16550-0", UART550_0_BASE, UART550_SIZE);
    create_unimplemented_device("uart16550-1", UART550_1_BASE, UART550_SIZE);

    /* --- XPS Central DMA (xlnx.opb-dma-channel) -------------------------
     * Confirmed base: 0x64010000 (XPAR_DMACHANNEL_0_BASEADDR).
     * Passes XDmaChannel_SelfTest: reset→DMAC=0x98000000.
     * Executes simple and scatter-gather transfers in guest RAM.
     * IRQ line: placeholder IRQ_DMA=2; real XIntc assignment TBD. */
    {
        DeviceState  *dma_dev = qdev_new("xlnx.opb-dma-channel");
        SysBusDevice *dma_sbd = SYS_BUS_DEVICE(dma_dev);
        sysbus_realize_and_unref(dma_sbd, &error_fatal);
        sysbus_mmio_map(dma_sbd, 0, DMA_BASE);
        sysbus_connect_irq(dma_sbd, 0, intc_irqs[IRQ_DMA]);
    }

    /* RED custom error-counter IP (probed early in boot, patches #40-42) */
    create_unimplemented_device("red-errctrs", ERRCTRS_BASE, ERRCTRS_SIZE);

    /* --- RED custom histogram/waveform IP cores (red.histogram-ip) ------
     * Five proprietary FPGA IP blocks in the sensor pipeline.
     * Firmware reads status registers during sysHwInit_seq but never
     * busy-polls; returning 0 for all reads causes the firmware to skip
     * the "histogram enabled" paths and continue boot cleanly.
     * IRQ lines are never asserted (no sensor data in emulation).
     *
     * Names / PLB addresses (from firmware device strings + xparameters.h):
     *   "Luma Histogram"  0xe0080000   "RGB Histogram"    0xe00a0000
     *   "RGB Comp Histo"  0xe0100000   "Mono Histogram"   0xe0120000
     *   "Luma Waveform"   0xe0200000
     * Size: 0x20000 each (128 KB) to cover all observed access offsets. */
    {
        static const hwaddr hist_bases[] = {
            HIST1_BASE,   /* Luma Histogram  0xe0080000 */
            HIST0_BASE,   /* RGB Histogram   0xe00a0000 */
            HIST2_BASE,   /* RGB Comp Histo  0xe0100000 */
            HIST3_BASE,   /* Mono Histogram  0xe0120000 */
            HIST4_BASE,   /* Luma Waveform   0xe0200000 */
        };
        unsigned i;
        for (i = 0; i < ARRAY_SIZE(hist_bases); i++) {
            DeviceState  *hd = qdev_new("red.histogram-ip");
            SysBusDevice *hs = SYS_BUS_DEVICE(hd);
            sysbus_realize_and_unref(hs, &error_fatal);
            sysbus_mmio_map(hs, 0, hist_bases[i]);
        }
    }

    /* --- XPS PCI v1.02a host bridge (xlnx.opb-pci-host) -----------------
     * Confirmed base: 0xe1200000 (XPAR_PCI_0_BASEADDR / PCI_CFG_BASE).
     * Exposes IPIF interrupt registers + CAR/CDR PCI config cycle port.
     * Bus is empty (all config reads return 0xFFFFFFFF = no device).
     * XPci_SelfTest() has no hardware access and always returns XST_SUCCESS.
     * SiI3512 SATA and ISP1562 USB stubs deferred to later phases. */
    {
        DeviceState  *pci_dev = qdev_new("xlnx.opb-pci-host");
        SysBusDevice *pci_sbd = SYS_BUS_DEVICE(pci_dev);
        sysbus_realize_and_unref(pci_sbd, &error_fatal);
        sysbus_mmio_map(pci_sbd, 0, PCI_CFG_BASE);
    }

    /* XPS IIC (I²C) */
    create_unimplemented_device("xps-iic", I2C_BASE, I2C_SIZE);

    /* PCI memory windows */
    create_unimplemented_device("pci-mem0",  PCI_MEM_BASE,  PCI_MEM_SIZE);
    create_unimplemented_device("pci-mem1",  PCI_MEM2_BASE, PCI_MEM2_SIZE);

    /* --- NOR flash (128 MB at 0xf0000000) and boot ROM (64 KB at 0xffff0000)
     * Both return 0xFF on reads (erased NOR flash state) and discard writes.
     * VxWorks TFFS CFI probe expects 0xFF from blank flash; returning 0x00
     * causes geometry-detection errors.  No persistent backing — flash writes
     * have no effect in emulation. */
    {
        MemoryRegion *nor = g_new(MemoryRegion, 1);
        memory_region_init_io(nor, NULL, &nor_flash_ops, NULL,
                              "nor-flash", NOR_FLASH_SIZE);
        memory_region_add_subregion(sysmem, NOR_FLASH_BASE, nor);
    }
    {
        MemoryRegion *rom = g_new(MemoryRegion, 1);
        memory_region_init_io(rom, NULL, &nor_flash_ops, NULL,
                              "boot-rom", BOOT_ROM_SIZE);
        memory_region_add_subregion(sysmem, BOOT_ROM_BASE, rom);
    }

    /* --- FPGA fabric catch-all (64 MB at 0xe0000000-0xe3ffffff) ----------
     * Silently absorbs reads/writes to FPGA peripherals not individually
     * modelled above (LCD DMA, colorimetry, CPLD GPIO, etc.) so the firmware
     * does not trigger Machine Check Exceptions on those addresses.
     * Priority -2000 keeps this region below all named devices mapped in the
     * same range (XIntc, XUartLite, XEmacLite, histograms, etc.).
     * Writes are forwarded to the LCD TCP bridge on port 17186. */
    {
        MemoryRegion *fpga = g_new(MemoryRegion, 1);
        memory_region_init_io(fpga, NULL, &fpga_catchall_ops, &g_lcd_bridge,
                              "r1mx.fpga-fabric", 64 * MiB);
        memory_region_add_subregion_overlap(sysmem, 0xe0000000u, fpga, -2000);
    }

    /* --- LCD TCP bridge (port 17186) ------------------------------------- */
    lcd_bridge_init(&g_lcd_bridge);

    (void)env; /* suppress unused-variable warning if no further env use */
}

/* ---------------------------------------------------------------------------
 * Machine class
 * --------------------------------------------------------------------------- */

static void r1mx_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc         = "RED ONE MX (Xilinx Virtex-4 FX, PPC405F6, VxWorks)";
    mc->init         = r1mx_init;
    mc->default_cpu_type = POWERPC_CPU_TYPE_NAME("x2vp4");
    mc->default_ram_size = 256 * MiB;
    /* No mc->default_ram_id — RAM is allocated directly in r1mx_init so it
     * ends up in ram_list via qemu_ram_alloc and TCG can always find it. */

    /* One NIC slot for the XEmacLite (WDB / host networking) */
    mc->default_nic = "xlnx.xps-ethernetlite";
}

static const TypeInfo r1mx_machine_typeinfo = {
    .name        = TYPE_R1MX_MACHINE,
    .parent      = TYPE_MACHINE,
    .instance_size = sizeof(R1mxState),
    .class_init  = r1mx_machine_class_init,
};

static void r1mx_machine_register(void)
{
    type_register_static(&r1mx_machine_typeinfo);
}

type_init(r1mx_machine_register)
