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
 *
 * Device activity monitor
 *   An activity broker listens on TCP localhost:17187 and broadcasts 32-byte
 *   "RDEV" packets for every MMIO read/write on the following devices:
 *     UARTLite, EthernetLite (via interposing MemoryRegion spy)
 *     OPB DMA, Histogram IPs (via per-device callback)
 *     FPGA catch-all (every unmodelled FPGA peripheral access)
 *
 *   Packet layout (32 bytes, all multi-byte fields big-endian):
 *     [0-3]   magic "RDEV"
 *     [4]     device_id  (R1MX_DEV_* from r1mx_activity.h)
 *     [5]     direction  'R'=0x52 / 'W'=0x57
 *     [6]     access size in bytes (1, 2, or 4)
 *     [7]     reserved 0
 *     [8-11]  guest physical address (uint32 big-endian)
 *     [12-15] value (uint32 big-endian, lower 32 bits of 64-bit val)
 *     [16-23] virtual-clock timestamp in nanoseconds (uint64 big-endian)
 *     [24-31] reserved 0
 *
 *   To start the GUI monitor:
 *     python3 -m toolkit.gui.emulator
 *   (from the r1mx toolkit directory, or run toolkit/gui/emulator.py directly)
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
#include "hw/char/serial.h"
#include "hw/loader.h"
#include "exec/address-spaces.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "net/net.h"
#include "qemu/main-loop.h"
#include "qemu/timer.h"
#include "hw/ppc/r1mx_activity.h"
#include "sysemu/block-backend.h"
#include "block/accounting.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>

/* ---------------------------------------------------------------------------
 * PLB address map (from PLB table at firmware offset 0xdfbbc8, re_reference §6)
 * --------------------------------------------------------------------------- */
#define UARTLITE_BASE   0xe0600000u  /* XPS UARTLite  — 115200 8N1, TX FIFO +4 */
#define UART550_0_BASE  0xe0640000u  /* XPS UART16550 #1 — not modelled        */
#define UART550_1_BASE  0xe0650000u  /* XPS UART16550 #2 — not modelled        */
#define INTC_BASE       0xe1200000u  /* XPS Interrupt Controller (corrected 2026-06-21:
                                      * firmware XIntc_LookupConfig cfg base = 0xe1200000,
                                      * not 0xe0800000 — xparameters.h was regenerated at
                                      * the wrong reloc and crossed XIntc/XIic/XPci) */
#define ERRCTRS_BASE    0xe0be0000u  /* RED custom error-counter IP            */
#define HIST0_BASE      0xe00a0000u  /* RED histogram IP 0                     */
#define HIST1_BASE      0xe0080000u  /* RED histogram IP 1                     */
#define HIST2_BASE      0xe0100000u  /* RED histogram IP 2                     */
#define HIST3_BASE      0xe0120000u  /* RED histogram IP 3                     */
#define HIST4_BASE      0xe0200000u  /* RED histogram IP 4                     */
#define ETHLITE_BASE    0xe1020000u  /* XPS EthernetLite — WDB endpoint        */
#define PCI_CFG_BASE    0xb2600000u  /* XPS PCI v3 (corrected: XPci_LookupConfig base
                                      * = 0xb2600000; CAR/CDR at +0x10C/+0x110)        */
#define I2C_BASE        0xe0800000u  /* XPS IIC (I²C) (corrected: XIic_LookupConfig
                                      * base = 0xe0800000, was wrongly the XIntc spot)  */
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

/* XIntc line assignments — CORRECTED 2026-06-21 from the firmware's live XIntc
 * HandlerTable (read at runtime; the prior 0/1/2/3/4 values were placeholders from
 * the mis-regenerated xparameters.h).  Confirmed device-per-line:
 *   line 0  — PCI host bridge (pciInt)
 *   line 4  — XUartNs550 (#0)
 *   line 22 — XEmacLite
 *   line 24 — XUartLite (console; interrupt-driven, enabled in IER)
 *   line 26 — XUartNs550 (#1)
 * Firmware-enabled IER bits at idle: 0, 4, 24, 26 (EmacLite line 22 enabled later).
 */
#define IRQ_PCI         0
#define IRQ_UART550_0   4
#define IRQ_ETHLITE     22
#define IRQ_UARTLITE    24
#define IRQ_UART550_1   26
#define IRQ_DMA         2   /* not in firmware table; kept as placeholder, harmless */

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
 * ATA/SATA host adapter — minimal "empty bay" model (PROTOTYPE)
 *
 * The VxWorks ataDrv polls the IDE task-file registers at the *bare* legacy
 * ports 0x1F0-0x1F7 (command block) and 0x3F6 (control block / AltStatus) --
 * confirmed un-rebased in the live image.  With no model these land on the low
 * exception-vector DRAM page and return code bytes; AltStatus@0x3F6 happens to
 * read 0x08 (BSY clear), which fools the reset/probe (FUN_0001f8f0) into
 * thinking a drive is present and ready -- it then issues a command and hangs
 * forever in ataPiWait (FUN_000206bc), which has no timeout.
 *
 * A real IDE/SATA channel with no media floats high: every task-file read is
 * 0xFF, so Status/AltStatus read with BSY (0x80) set.  Returning 0xFF here lets
 * the firmware's own tick-bounded probe time out (now that the PIT runs) and
 * conclude "no drive", so boot continues -- the faithful empty-bay path that
 * the hot-plug monitor task tSataMon expects.
 *
 * PROTOTYPE: overlaid at the literal legacy CPU-physical addresses.  Whether
 * the real board decodes those addresses directly (a) or rebases the table to a
 * PCI-I/O window via the SATA BAR (b) is pending the live-HW read
 * (plans/ata_live_hw_read.md).  Once known, this becomes either a low-address
 * overlay or a proper PCI SATA function.  See boot_reconstruction_status.md.
 * --------------------------------------------------------------------------- */
static uint64_t ata_empty_read(void *opaque, hwaddr offset, unsigned size)
{
    /* Floating IDE bus with no device: all bits high (BSY set on status regs). */
    return 0xFFFFFFFFFFFFFFFFULL >> (64 - size * 8);
}

static void ata_empty_write(void *opaque, hwaddr offset,
                            uint64_t val, unsigned size)
{
    /* No device to latch register writes (incl. SRST to DevControl). */
}

static const MemoryRegionOps ata_empty_ops = {
    .read       = ata_empty_read,
    .write      = ata_empty_write,
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
 * Activity broker (port 17187)
 *
 * Broadcasts 32-byte "RDEV" packets for every MMIO access on any hooked
 * device.  At most one GUI client is accepted at a time; a new connection
 * drops the previous one.  All errors are non-fatal.
 * --------------------------------------------------------------------------- */
#define ACTIVITY_TCP_PORT  17187

typedef struct R1mxActivityBroker {
    int listen_fd;   /* server socket (O_NONBLOCK), -1 if unavailable */
    int client_fd;   /* accepted client, -1 if disconnected           */
} R1mxActivityBroker;

static R1mxActivityBroker g_activity_broker = { .listen_fd = -1,
                                                 .client_fd = -1 };

/* Forward declarations — sampler symbols are defined further below but are
 * referenced in activity_broker_accept which must precede them in the file. */
#define CPU_SAMPLE_NS_FWD    500000ULL
#define BLOCK_SAMPLE_NS_FWD  10000000ULL
typedef struct R1mxCpuSampler {
    QEMUTimer  *timer;
    PowerPCCPU *cpu;
} R1mxCpuSampler;
static R1mxCpuSampler  g_cpu_sampler;
static QEMUTimer      *g_block_sampler_timer;
static bool            g_samplers_enabled = false;

static void activity_broker_accept(void *opaque)
{
    R1mxActivityBroker *br = opaque;
    int fd = accept(br->listen_fd, NULL, NULL);
    if (fd < 0) {
        return;
    }
    if (br->client_fd >= 0) {
        close(br->client_fd);
    }
    br->client_fd = fd;
    {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    /* Start the samplers now that a client is connected, but only when
     * -machine …,activity-samplers=on was given.  Both timers are
     * self-stopping (they check client_fd in their tick) so they cease
     * automatically if the client later disconnects. */
    if (g_samplers_enabled) {
        timer_mod(g_cpu_sampler.timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + CPU_SAMPLE_NS_FWD);
        timer_mod(g_block_sampler_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + BLOCK_SAMPLE_NS_FWD);
    }
}

static void activity_broker_init(R1mxActivityBroker *br)
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
    addr.sin_port        = htons(ACTIVITY_TCP_PORT);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, 1) < 0) {
        close(fd);
        return;
    }

    br->listen_fd = fd;
    qemu_set_fd_handler(fd, activity_broker_accept, NULL, br);
}

/*
 * activity_broker_send — emit one 32-byte RDEV packet.
 *
 * This is the low-level sender; most callers go via the R1mxActivityCb
 * trampoline installed on each device or via the spy region ops below.
 */
static void activity_broker_send(R1mxActivityBroker *br,
                                  uint8_t dev_id, uint8_t dir,
                                  uint32_t addr, uint64_t val, unsigned size)
{
    uint8_t  pkt[32];
    uint64_t ts;

    if (br->client_fd < 0) {
        return;
    }

    ts = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    pkt[0] = 'R'; pkt[1] = 'D'; pkt[2] = 'E'; pkt[3] = 'V';
    pkt[4]  = dev_id;
    pkt[5]  = dir;
    pkt[6]  = (uint8_t)size;
    pkt[7]  = 0;
    pkt[8]  = (addr >> 24) & 0xff;
    pkt[9]  = (addr >> 16) & 0xff;
    pkt[10] = (addr >>  8) & 0xff;
    pkt[11] =  addr        & 0xff;
    pkt[12] = (val  >> 24) & 0xff;
    pkt[13] = (val  >> 16) & 0xff;
    pkt[14] = (val  >>  8) & 0xff;
    pkt[15] =  val         & 0xff;
    pkt[16] = (ts   >> 56) & 0xff;
    pkt[17] = (ts   >> 48) & 0xff;
    pkt[18] = (ts   >> 40) & 0xff;
    pkt[19] = (ts   >> 32) & 0xff;
    pkt[20] = (ts   >> 24) & 0xff;
    pkt[21] = (ts   >> 16) & 0xff;
    pkt[22] = (ts   >>  8) & 0xff;
    pkt[23] =  ts          & 0xff;
    memset(pkt + 24, 0, 8);

    if (send(br->client_fd, pkt, sizeof(pkt), MSG_NOSIGNAL) < 0) {
        close(br->client_fd);
        br->client_fd = -1;
    }
}

/*
 * R1mxActivityCb trampoline — installed on per-device callback fields.
 * opaque points to g_activity_broker.
 */
static void activity_broker_cb(uint8_t dev_id, uint8_t dir,
                                uint32_t addr, uint64_t val, unsigned size,
                                void *opaque)
{
    activity_broker_send((R1mxActivityBroker *)opaque,
                          dev_id, dir, addr, val, size);
}

/* ---------------------------------------------------------------------------
 * Spy MemoryRegion — transparent interposing region
 *
 * Mapped at higher priority (1) over the real device's region.  Every read
 * and write is logged to the activity broker and then forwarded directly to
 * the underlying device's MMIO ops, bypassing the address-space layer so
 * there is no infinite interposition loop.
 *
 * Endianness: the spy uses DEVICE_BIG_ENDIAN (same as all R1MX devices).
 * The real device's ops->read/write are called with the same (offset, size)
 * that the spy received, so the endianness contract is identical.
 *
 * NOTE: this technique requires that the real device uses flat MMIO ops
 * (not a container MemoryRegion).  Both XPS UARTLite and XPS EthernetLite
 * satisfy this requirement.
 * --------------------------------------------------------------------------- */
typedef struct R1mxSpyRegion {
    MemoryRegion       mr;
    MemoryRegion      *real_mr;   /* the real device's MMIO region */
    uint8_t            dev_id;
    uint32_t           base;      /* guest physical base address   */
    MemoryRegionOps    ops;       /* per-instance copy so endianness/size can vary */
} R1mxSpyRegion;

static uint64_t spy_read(void *opaque, hwaddr offset, unsigned size)
{
    R1mxSpyRegion *spy = opaque;
    uint64_t val = 0;

    if (spy->real_mr->ops && spy->real_mr->ops->read) {
        val = spy->real_mr->ops->read(spy->real_mr->opaque, offset, size);
    }
    activity_broker_send(&g_activity_broker, spy->dev_id, R1MX_DIR_READ,
                          spy->base + (uint32_t)offset, val, size);
    return val;
}

static void spy_write(void *opaque, hwaddr offset,
                       uint64_t val, unsigned size)
{
    R1mxSpyRegion *spy = opaque;

    activity_broker_send(&g_activity_broker, spy->dev_id, R1MX_DIR_WRITE,
                          spy->base + (uint32_t)offset, val, size);
    if (spy->real_mr->ops && spy->real_mr->ops->write) {
        spy->real_mr->ops->write(spy->real_mr->opaque, offset, val, size);
    }
}

/* Allocate and install a spy region over [base, base+size).
 * The spy's ops are initialised to exactly match the real device's declared
 * endianness and valid access-size constraints so QEMU's memory dispatch
 * layer applies the same byte-swap and size-splitting logic for both. */
static void install_spy(MemoryRegion *sysmem, SysBusDevice *sbd,
                         unsigned mmio_idx, hwaddr base, uint64_t spy_size,
                         uint8_t dev_id, const char *name)
{
    R1mxSpyRegion *spy = g_new0(R1mxSpyRegion, 1);
    spy->real_mr = sysbus_mmio_get_region(sbd, mmio_idx);
    spy->dev_id  = dev_id;
    spy->base    = (uint32_t)base;
    /* Mirror the real device's endianness and access-size constraints exactly
     * so the dispatch layer applies identical byte-swapping to the spy as it
     * would to the real region.  Without this the guest sees double-swapped
     * register values on a little-endian host. */
    spy->ops.read            = spy_read;
    spy->ops.write           = spy_write;
    spy->ops.endianness      = spy->real_mr->ops->endianness;
    spy->ops.valid.min_access_size =
        spy->real_mr->ops->valid.min_access_size
        ? spy->real_mr->ops->valid.min_access_size : 1;
    spy->ops.valid.max_access_size =
        spy->real_mr->ops->valid.max_access_size
        ? spy->real_mr->ops->valid.max_access_size : 4;
    memory_region_init_io(&spy->mr, NULL, &spy->ops, spy, name, spy_size);
    /* priority 1 > default 0: spy wins over the real device region */
    memory_region_add_subregion_overlap(sysmem, base, &spy->mr, 1);
}

/*
 * install_spy_mr — same as install_spy but takes a plain MemoryRegion pointer
 * directly rather than a SysBusDevice MMIO slot.  Used to wrap NOR flash and
 * boot ROM regions that are not sysbus devices.
 */
static void install_spy_mr(MemoryRegion *sysmem, MemoryRegion *real_mr,
                            hwaddr base, uint64_t spy_size, uint8_t dev_id,
                            const char *name)
{
    R1mxSpyRegion *spy = g_new0(R1mxSpyRegion, 1);
    spy->real_mr = real_mr;
    spy->dev_id  = dev_id;
    spy->base    = (uint32_t)base;
    spy->ops.read            = spy_read;
    spy->ops.write           = spy_write;
    spy->ops.endianness      = real_mr->ops->endianness;
    spy->ops.valid.min_access_size =
        real_mr->ops->valid.min_access_size
        ? real_mr->ops->valid.min_access_size : 1;
    spy->ops.valid.max_access_size =
        real_mr->ops->valid.max_access_size
        ? real_mr->ops->valid.max_access_size : 4;
    memory_region_init_io(&spy->mr, NULL, &spy->ops, spy, name, spy_size);
    memory_region_add_subregion_overlap(sysmem, base, &spy->mr, 1);
}

/* ---------------------------------------------------------------------------
 * FPGA fabric catch-all MMIO region (0xe0000000 - 0xe3ffffff, 64 MB)
 *
 * Absorbs accesses to FPGA peripherals not yet individually modelled so that
 * the firmware does not trigger Machine Check Exceptions on those addresses.
 * Reads return 0 (and are reported); writes are forwarded to both the LCD TCP
 * bridge and the activity broker.
 * Priority -2000 keeps this region BELOW all named devices mapped in the same
 * address range (XIntc at 0xe0800000, XUartLite at 0xe0600000, etc.).
 * --------------------------------------------------------------------------- */
static uint64_t fpga_catchall_read(void *opaque, hwaddr offset, unsigned size)
{
    (void)opaque;
    activity_broker_send(&g_activity_broker, R1MX_DEV_FPGA, R1MX_DIR_READ,
                          (uint32_t)(0xe0000000u + offset), 0, size);
    return 0;
}

static void fpga_catchall_write(void *opaque, hwaddr offset,
                                uint64_t val, unsigned size)
{
    R1mxLcdBridge *br = opaque;
    lcd_bridge_send(br, (uint32_t)(0xe0000000u + offset), val, size);
    activity_broker_send(&g_activity_broker, R1MX_DEV_FPGA, R1MX_DIR_WRITE,
                          (uint32_t)(0xe0000000u + offset), val, size);
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
    bool            activity_samplers; /* -machine …,activity-samplers=on */
} R1mxState;

#define TYPE_R1MX_MACHINE   MACHINE_TYPE_NAME("r1mx-virtex4")
DECLARE_INSTANCE_CHECKER(R1mxState, R1MX_MACHINE, TYPE_R1MX_MACHINE)

/* ---------------------------------------------------------------------------
 * CPU + RAM periodic activity sampler
 *
 * A QEMUTimer fires every CPU_SAMPLE_NS of virtual time (only while the VM
 * is running) and emits:
 *   R1MX_DEV_CPU  addr=current PC,  value=1 running / 0 halted, dir='R'
 *   R1MX_DEV_RAM  addr=current PC,  value=1,                    dir='R'
 *                 (only when CPU is running — implies instruction fetch)
 *
 * Using QEMU_CLOCK_VIRTUAL means the timer advances only while the guest
 * clock ticks, so no spurious packets are sent when the machine is paused.
 * --------------------------------------------------------------------------- */
#define CPU_SAMPLE_NS  500000ULL   /* 500 µs virtual time between samples */

static void cpu_sampler_tick(void *opaque)
{
    R1mxCpuSampler *s      = (R1mxCpuSampler *)opaque;
    CPUState       *cs     = CPU(s->cpu);
    uint32_t        pc     = (uint32_t)s->cpu->env.nip;
    int             halted = cs->halted || cs->stopped;

    activity_broker_send(&g_activity_broker, R1MX_DEV_CPU, R1MX_DIR_READ,
                          pc, halted ? 0u : 1u, 4);

    if (!halted) {
        activity_broker_send(&g_activity_broker, R1MX_DEV_RAM, R1MX_DIR_READ,
                              pc, 1, 4);
    }

    /* Only reschedule while a GUI client is connected; timer stops otherwise
     * so there is zero overhead on the emulator when no client is attached. */
    if (g_activity_broker.client_fd >= 0) {
        timer_mod(s->timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + CPU_SAMPLE_NS);
    }
}

static void cpu_sampler_init(R1mxCpuSampler *s, PowerPCCPU *cpu)
{
    s->cpu   = cpu;
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, cpu_sampler_tick, s);
    /* Timer is NOT armed here.  It is started by activity_broker_accept()
     * when the first GUI client connects, and stops itself in
     * cpu_sampler_tick() when the client disconnects.  This ensures zero
     * timer overhead when no monitor is open. */
}

/* ---------------------------------------------------------------------------
 * Block-device activity sampler
 *
 * Polls BlockAcctStats on attached block backends every BLOCK_SAMPLE_NS of
 * real time.  The first backend maps to R1MX_DEV_SDCARD (CF / SD recording
 * media), the second to R1MX_DEV_SSD (SiI3512 SATA SSD bay).
 *
 * Direction R1MX_DIR_READ  → bytes read  since last tick (value = KB)
 * Direction R1MX_DIR_WRITE → bytes written since last tick (value = KB)
 * addr = 0 (block devices have no single MMIO address)
 *
 * Uses QEMU_CLOCK_REALTIME so block I/O during guest pause is still visible.
 * --------------------------------------------------------------------------- */
#define BLOCK_SAMPLE_NS  10000000ULL   /* 10 ms real time between polls */

static uint64_t         g_blk_rd[2];         /* last-sampled nr_bytes read  */
static uint64_t         g_blk_wr[2];         /* last-sampled nr_bytes write */
static const uint8_t    g_blk_dev_ids[2] = { R1MX_DEV_SDCARD, R1MX_DEV_SSD };

static void block_sampler_tick(void *opaque)
{
    BlockBackend *blk  = NULL;
    int           slot = 0;

    while ((blk = blk_next(blk)) != NULL && slot < 2) {
        BlockAcctStats *stats = blk_get_stats(blk);
        uint8_t  dev_id = g_blk_dev_ids[slot];
        uint64_t rd     = stats->nr_bytes[BLOCK_ACCT_READ];
        uint64_t wr     = stats->nr_bytes[BLOCK_ACCT_WRITE];

        if (rd > g_blk_rd[slot]) {
            /* value = KB read (>>10), clamped to 32 bits */
            uint64_t delta = rd - g_blk_rd[slot];
            activity_broker_send(&g_activity_broker, dev_id, R1MX_DIR_READ,
                                  0, (uint32_t)(delta >> 10), 4);
            g_blk_rd[slot] = rd;
        }
        if (wr > g_blk_wr[slot]) {
            uint64_t delta = wr - g_blk_wr[slot];
            activity_broker_send(&g_activity_broker, dev_id, R1MX_DIR_WRITE,
                                  0, (uint32_t)(delta >> 10), 4);
            g_blk_wr[slot] = wr;
        }
        slot++;
    }

    /* Only reschedule while a GUI client is connected. */
    if (g_activity_broker.client_fd >= 0) {
        timer_mod(g_block_sampler_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + BLOCK_SAMPLE_NS);
    }
}

static void block_sampler_init(void)
{
    g_block_sampler_timer = timer_new_ns(QEMU_CLOCK_REALTIME,
                                          block_sampler_tick, NULL);
    /* Not armed at startup — started by activity_broker_accept(). */
}

/* ---------------------------------------------------------------------------
 * Boot-environment fixups
 *
 * The RED ONE MX firmware (software.bin) is a RAM image loaded flat at phys 0x0
 * via -device loader.  Three things the real camera's boot environment provides
 * are absent in that flat-load model; we supply them here instead of patching
 * the firmware binary (formerly patch_firmware.py #1/#2/#3, now retired):
 *
 *   #1  romInit (0x84) sets the early boot SP to 0x0000FFF0, which collides with
 *       the loaded image (the deep usrInit call chain grows the stack down into
 *       the exception vectors / low code).  On hardware romInit runs from flash
 *       and low RAM is scratch.  Relocate the boot SP above the image by writing
 *       `lis r1,0x800` (SP -> 0x07FFFFF0) at 0x84.
 *
 *   #2/#3  Early boot spins at 0x36C380 until the VxWorks canary words appear at
 *       0xE269A0/0xE269A4 -- written by a separate init agent that does not run
 *       in single-core emulation.  Seed the two canary VALUES so the spin exits
 *       (no code NOP needed; this models the agent's effect).
 *
 *   #4/#5  Root-task dispatch.  FUN_00371cd0 (task-context setup) branches:
 *       `if (*0xE3A790 == TCB+0x94)` -> IF-path saves PC = 0x381A8C (a mid-routine
 *       address in the OpenSSL X.509 code; the "artifact dispatch" that firmware
 *       patches #53/55 produce -- NEITHER the original 0x381AEC nor the patched
 *       0x381A8C is a real trampoline); ELSE-path saves PC = TCB+0xC0 (the task's
 *       own entry, = usrRoot 0x37C440 for the root task -- verified static).
 *       TCB+0x94 is COPIED from *0xE3A790 at task setup, so seeding the selector
 *       can't break the match (it propagates).  On hardware *0xE3A790 changes
 *       between root-task creation and its first dispatch (live value 0x00FC9580,
 *       no static writer) so the root task takes the else-path; that timing can't
 *       be reproduced by a static seed.  Instead we FORCE the else-path: patch the
 *       branch `bne 0x371D78` (4082001C) at 0x371D5C to `b 0x371D78` (4800001C),
 *       so every task dispatches to its own TCB+0xC0 entry (normal VxWorks
 *       behaviour; the if-path artifact + patches #53/55 become dead code).  The
 *       else-path calls *0xE293F4 only if non-zero; the stale .data 0x542974 (a
 *       function epilogue) would crash, so seed *0xE293F4 = 0 (the live value) to
 *       skip it.  This makes the NATURAL firmware dispatch reach usrRoot with a
 *       real task context, replacing firmware patches #53/55.  (Dispatch logic
 *       harvested/verified against live cam-working-01, 2026-06-14; see
 *       boot_reconstruction_status.md.)
 *
 *   #6  usrRoot TRUE-ENTRY redirect (2026-06-17).  usrInit (main_boot_init,
 *       0x36C350) calls kernelInit(rootRtn=0x37C440, ...).  0x37C440 is a
 *       mid-function RESUME label (`b 0x37c290`) inside usrRoot (the function
 *       starts at the prologue 0x37BF78), NOT a clean entry: it assumes r30 is
 *       already 0xEA0000.  With the else-path forced (#4/#5) the root task
 *       dispatches straight to TCB+0xC0 = 0x37C440 with r30 = 0, so the
 *       dispatcher block at 0x37c290 (`lwz r9,-0x3c20(r30); stw r3,0x278(r9)`)
 *       reads *0xFFFFC3E0 and writes through it, clobbering the PCI config-address
 *       builder instruction at 0x274 (`or r3,r3,r5` 0x7c632b78 -> illegal) ->
 *       SILENTLY breaks every PCI config read.  Fix: redirect rootRtn to usrRoot's
 *       TRUE entry 0x37BF78 so its prologue runs and sets r30 = 0xEA0000 itself
 *       (no register injection; maximally faithful).  Patch the immediate built at
 *       0x36C414 `addi r3,r3,-0x3bc0` (0x37C440) -> `addi r3,r3,-0x4088` (0x37BF78);
 *       the preceding `lis r3,0x38` (0x36C40C) is unchanged.  Companions, all
 *       cold-.data garbage the bypassed early init would have set (same class as
 *       the canary/gate seeds): *0xE2706C = 0 (usrRoot's per-call state flag, which
 *       usrRoot only ever toggles 0<->1; cold garbage 0x005170c8 -> the true entry
 *       would take the init-pass branch and return — seed 0 so it falls straight
 *       through the main body in one pass and sets r30) and the deferred-write list
 *       head/tail at 0xE9C5C0/0xE9C5C4 -> self (empty ring), required by the
 *       prologue's deferred-write walker 0x37d87c.  VERIFIED (drive_enum.py /
 *       lockstep): with these, the natural dispatch enters 0x37BF78, r30 is set by
 *       the prologue, and 0x274 stays 0x7c632b78 (no corruption).  NB the free-run
 *       natural boot then meets the broader init-bypass cascade (a clean 0x700 deep
 *       in early usrRoot) — the documented irreducible wall; the faithful
 *       device-init / PCI-enum path remains the harness-driven one (drive_enum.py),
 *       now corruption-free.  See boot_reconstruction_status.md 2026-06-16/17.
 *
 *   #7  Allocator guard-zone seed (2026-06-17).  RED's memPartLib per-allocation
 *       guard/red-zone size global *0xE295E4 is cold-.data garbage 0x00d8fad0
 *       (~14 MB); nothing in the allocator init writes it (read-only config const
 *       set by the bypassed early data init).  Left nonzero it makes addToPool
 *       waste ~14 MB at the pool front and the carve overhead so large that the
 *       FIRST malloc takes the no-split branch and empties the free tree (only one
 *       malloc serviceable).  Seed 0 (guards off, the production default) so the
 *       allocator services unlimited mallocs (e.g. the PCI enum's per-device
 *       descriptors).  See boot_reconstruction_status.md 2026-06-17.
 *
 * Run as a reset handler registered from a machine-init-done notifier, so it
 * executes AFTER the -device loader has populated RAM, on every reset.
 * --------------------------------------------------------------------------- */

#define VXWORKS_CANARY_1_ADDR  0x00E269A4u   /* expects 0x12348765 */
#define VXWORKS_CANARY_2_ADDR  0x00E269A0u   /* expects 0x5A5AC3C3 */
#define DISPATCH_BRANCH_ADDR   0x00371D5Cu   /* bne 0x371D78 -> b (force else-path) */
#define DISPATCH_FNPTR_ADDR    0x00E293F4u   /* *0xE293F4: NULL -> skip stale call  */
#define PCI_CFG_GATE_ADDR      0x00E0BDFCu   /* XPci config gate: must be -1 to register */
#define ROOTRTN_ADDI_ADDR      0x0036C414u   /* addi r3,r3,-0x3bc0 (0x37C440) -> -0x4088 */
#define USRROOT_STATE_ADDR     0x00E2706Cu   /* usrRoot per-call state flag: garbage -> 0 */
#define DEFER_LIST_HEAD_ADDR   0x00E9C5C0u   /* deferred-write list head -> self (empty)   */
#define DEFER_LIST_TAIL_ADDR   0x00E9C5C4u   /* deferred-write list tail -> self (empty)   */
#define ALLOC_GUARDZONE_ADDR   0x00E295E4u   /* memPartLib guard/red-zone size: garbage -> 0 */

/* Apply the boot-environment fixups directly to RAM.  Run from a VM-state-change
 * handler on the transition to RUNNING: this fires after the -device loader's
 * force-raw load_image_targphys has populated RAM (which in this QEMU happens
 * after machine-init-done and after reset), and before the vCPU executes, so the
 * boot SP relocation is in place before romInit fetches it. */
static void r1mx_apply_boot_env_fixups(void *opaque, bool running, RunState state)
{
    static const uint8_t boot_sp_reloc[4] = { 0x3c, 0x20, 0x08, 0x00 }; /* lis r1,0x800 */
    static const uint8_t canary1[4]       = { 0x12, 0x34, 0x87, 0x65 };
    static const uint8_t canary2[4]       = { 0x5a, 0x5a, 0xc3, 0xc3 };
    static const uint8_t disp_force_else[4]= { 0x48, 0x00, 0x00, 0x1c }; /* b 0x371D78   */
    static const uint8_t disp_fnptr[4]    = { 0x00, 0x00, 0x00, 0x00 }; /* NULL -> skip  */
    /* XPci config gate: hw_seq_init's FUN_0000019c registers the config mechanism
     * (CAR/CDR) only if *0xE0BDFC == -1 first; cold .data holds garbage
     * (0x943c5669) so the registration silently no-ops and every config cycle
     * returns -1.  No code outside FUN_0000019c writes this slot, so seed it to
     * -1 here (same class as the canary/dispatch seeds — pending the real
     * pre-hw_seq_init initialiser).  Verified: with this, FUN_0000019c sets
     * gate=0/mech=1/CAR=0xB260010C/CDR=0xB2600110.  (2026-06-15) */
    static const uint8_t pci_cfg_gate[4]  = { 0xff, 0xff, 0xff, 0xff }; /* -1 -> register */
    /* #6 usrRoot true-entry redirect + companions (see header comment). */
    static const uint8_t rootrtn_addi[4]  = { 0x38, 0x63, 0xbf, 0x78 }; /* addi r3,r3,-0x4088 */
    static const uint8_t usrroot_state[4] = { 0x00, 0x00, 0x00, 0x00 }; /* state flag -> 0    */
    static const uint8_t defer_self[4]    = { 0x00, 0xe9, 0xc5, 0xc0 }; /* list node -> &head  */
    /* #7 allocator guard-zone -> 0 (guards off; repeated-malloc-capable). */
    static const uint8_t alloc_guardzone[4] = { 0x00, 0x00, 0x00, 0x00 };

    uint8_t at84[4], at_addi[4];

    if (!running) {
        return;
    }
    /* Only fix up when THIS firmware is actually loaded: 0x84 must hold romInit's
     * original `lis r1,1` (3c200001).  Guards device-only / no-firmware runs
     * (RAM is zero) and avoids re-applying once we've already relocated. */
    cpu_physical_memory_read(0x00000084u, at84, 4);
    if (at84[0] != 0x3c || at84[1] != 0x20 || at84[2] != 0x00 || at84[3] != 0x01) {
        return;
    }
    cpu_physical_memory_write(0x00000084u,           boot_sp_reloc, 4);
    cpu_physical_memory_write(VXWORKS_CANARY_1_ADDR,  canary1, 4);
    cpu_physical_memory_write(VXWORKS_CANARY_2_ADDR,  canary2, 4);
    cpu_physical_memory_write(DISPATCH_BRANCH_ADDR,   disp_force_else, 4);
    cpu_physical_memory_write(DISPATCH_FNPTR_ADDR,    disp_fnptr, 4);
    cpu_physical_memory_write(PCI_CFG_GATE_ADDR,      pci_cfg_gate, 4);

    /* #6 Redirect the root routine to usrRoot's true entry 0x37BF78 (the prologue
     * that sets r30), only if the original 0x37C440 immediate is present
     * (`addi r3,r3,-0x3bc0` = 38 63 c4 40), and seed its state-flag/deferred-write
     * companions so the prologue path runs in one pass without corrupting 0x274. */
    cpu_physical_memory_read(ROOTRTN_ADDI_ADDR, at_addi, 4);
    if (at_addi[0] == 0x38 && at_addi[1] == 0x63 &&
        at_addi[2] == 0xc4 && at_addi[3] == 0x40) {
        cpu_physical_memory_write(ROOTRTN_ADDI_ADDR,    rootrtn_addi, 4);
    }
    cpu_physical_memory_write(USRROOT_STATE_ADDR,   usrroot_state, 4);
    cpu_physical_memory_write(DEFER_LIST_HEAD_ADDR, defer_self, 4);
    cpu_physical_memory_write(DEFER_LIST_TAIL_ADDR, defer_self, 4);

    /* #7 Allocator guard-zone -> 0 (repeated-malloc-capable). */
    cpu_physical_memory_write(ALLOC_GUARDZONE_ADDR, alloc_guardzone, 4);
}

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

    /* Latch the activity-samplers flag before any device init. */
    g_samplers_enabled = R1MX_MACHINE(machine)->activity_samplers;

    /* --- Bare PPC405 CPU ------------------------------------------------- */
    cpu = POWERPC_CPU(cpu_create(machine->cpu_type));
    env = &cpu->env;

    /* Make cpu_reset() restore PVR to the Virtex-4 PPC405F6 value.
     * ppc_cpu_reset_hold() resets ALL SPRs to their default_value, so we
     * patch the default here before the first reset runs. */
    env->spr_cb[SPR_PVR].default_value = 0x20011000;
    env->spr[SPR_PVR]                  = 0x20011000;

    /* PPC405 init_excp_4xx_softmmu sets hreset_vector = 0xFFFFFFFCUL (boot ROM).
     * software.bin is a position-dependent VxWorks RAM image LINKED FOR BASE 0x10000
     * (the -device loader places it at 0x10000; romInit is at file offset 0 ->
     * runtime 0x10000).  Override hreset_vector so every cpu_reset() lands there.
     * This load base is what makes the firmware's own .data initialisers AND its
     * absolute code pointers resolve correctly; at base 0x0 every stored pointer and
     * global was 0x10000 too high -- the long "garbage fn-ptr / circular bootstrap"
     * saga was entirely this load-base error.  See boot_reconstruction_status.md
     * 2026-06-20. */
    env->hreset_vector = 0x00010000UL;

    /* PPC405 needs the 40x timer helpers (PIT/FIT/WDT).
     * Do NOT use ppc_booke_timers_init here — that is for PPC440 (Book-E).
     * ppc_40x_timers_init allocates the wdt_timer that store_40x_tcr requires. */
    ppc_40x_timers_init(env, 400000000, PPC_INTERRUPT_PIT);

    /* Register a CPU reset handler — same pattern as ppc440_bamboo.c */
    qemu_register_reset((QEMUResetHandler *)cpu_reset, cpu);

    /* CPU + RAM activity sampler — fires every 5 ms virtual time */
    cpu_sampler_init(&g_cpu_sampler, cpu);

    /* Boot-environment fixups DISABLED 2026-06-20.  Every one was a symptom-patch
     * for the wrong load base (0x0 instead of 0x10000): the canaries, PCI gate,
     * guard-zone, dispatch-fnptr and usrRoot-state seeds are just the firmware's own
     * .data initialisers, now loaded correctly at base 0x10000; the code patches
     * (#4/#5 @0x371D5C, #6 @0x36C414) would corrupt the wrong instructions at the
     * shifted base.  Boot native.  (Function kept above for reference / git history.)
     * See boot_reconstruction_status.md 2026-06-20. */
    /* qemu_add_vm_change_state_handler(r1mx_apply_boot_env_fixups, NULL); */
    (void)r1mx_apply_boot_env_fixups;  /* retained for reference; silence unused */

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
    sysbus_mmio_map(intc_sbd, 0, INTC_BASE);   /* now 0xe1200000 (corrected) */
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
        /* UartLite is on XIntc line 24 (confirmed from the firmware HandlerTable:
         * line 24 = XUartLite_InterruptHandler, enabled in IER).  The old line-0
         * placeholder collided with PCI (pciInt) and stormed. */
        sysbus_connect_irq(uart_sbd, 0, intc_irqs[IRQ_UARTLITE]);
        /* Spy region intercepts all UARTLite accesses for the activity monitor.
         * UARTLite register space is 16 bytes (4 regs × 4 bytes). */
        install_spy(sysmem, uart_sbd, 0, UARTLITE_BASE, 0x10, R1MX_DEV_UART,
                     "xlnx.xps-uartlite");
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
        /* Spy region covers the full dual-buffer ping-pong address space
         * (Xilinx DS599: 0x20000 bytes for 2×TX + 2×RX + control regs). */
        install_spy(sysmem, eth_sbd, 0, ETHLITE_BASE, 0x20000, R1MX_DEV_ETHERNET,
                     "xlnx.xps-ethernetlite");
    }

    /* --- Unimplemented / stub regions ------------------------------------ */

    /* XPS UART16550 #1 and #2 (not used for debug; firmware probes them)
     * NOTE: XUN_REG_OFFSET = 0x1000 — the NS550 driver accesses registers
     * starting at base+0x1000 (RBR at +0x1003, highest at +0x101F).
     * UART550_SIZE must be > 0x1020 to avoid MCE on those accesses. */
    create_unimplemented_device("uart16550-0", UART550_0_BASE, UART550_SIZE);
    create_unimplemented_device("uart16550-1", UART550_1_BASE, UART550_SIZE);

    /* Real XUartNs550 (16550) consoles. The Xilinx 16550 core sits at
     * base + XUN_REG_OFFSET (0x1000) with 32-bit register spacing (regshift=2)
     * and the 8-bit register in the LSB byte (big-endian) -- the driver hits
     * base+0x1000 + reg*4 + 3. serial_mm computes reg = (offset >> regshift),
     * so a serial-mm region based at base+0x1000 resolves those accesses
     * ((reg*4+3) >> 2 == reg). VxWorks routes its console + shell to one of
     * these NS550s (the XUartLite only carries boot-ROM diagnostics), so wiring
     * them to chardevs surfaces the boot banner, boot line and shell prompt.
     * Mapped at priority 0 over the -1000 unimplemented stubs above (no overlap
     * abort: those were added with add_subregion_overlap). IRQ lines are
     * placeholders -- correct for TX (console output); RX/shell input may need
     * the real XIntc line once known. serial_hd(0) is the XUartLite; NS550s use
     * serial_hd(1)/(2). */
    serial_mm_init(sysmem, UART550_0_BASE + 0x1000, 2, intc_irqs[IRQ_UART550_0],
                   115200 * 16, serial_hd(1), DEVICE_BIG_ENDIAN);
    serial_mm_init(sysmem, UART550_1_BASE + 0x1000, 2, intc_irqs[IRQ_UART550_1],
                   115200 * 16, serial_hd(2), DEVICE_BIG_ENDIAN);

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
        xlnx_opb_dma_set_activity(dma_dev, R1MX_DEV_DMA,
                                   activity_broker_cb, &g_activity_broker);
        xlnx_opb_dma_set_base(dma_dev, DMA_BASE);
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
        static const uint8_t hist_dev_ids[] = {
            R1MX_DEV_HIST_LUMA,
            R1MX_DEV_HIST_RGB,
            R1MX_DEV_HIST_RGBC,
            R1MX_DEV_HIST_MONO,
            R1MX_DEV_HIST_WAVE,
        };
        for (i = 0; i < (int)ARRAY_SIZE(hist_bases); i++) {
            DeviceState  *hd = qdev_new("red.histogram-ip");
            SysBusDevice *hs = SYS_BUS_DEVICE(hd);
            sysbus_realize_and_unref(hs, &error_fatal);
            sysbus_mmio_map(hs, 0, hist_bases[i]);
            red_histogram_ip_set_activity(hd, hist_dev_ids[i],
                                           activity_broker_cb,
                                           &g_activity_broker);
            red_histogram_ip_set_base(hd, (uint32_t)hist_bases[i]);
        }
    }

    /* --- XPS PCI v1.02a host bridge (xlnx.opb-pci-host) -----------------
     * Confirmed base: 0xe1200000 (XPAR_PCI_0_BASEADDR / PCI_CFG_BASE).
     * Exposes IPIF interrupt registers + CAR/CDR PCI config cycle port.
     * Bus 0 is populated by the bridge itself (dev 0) plus two ISP1562 USB
     * host-controller leaf devices (dev 1 = class 0x0C03A0, dev 2 = class
     * 0x0C0320) which the cold-boot enumerator FUN_00367f54 scans for; without
     * them the device count (0xE26978) stays 0 and the keystone allocator
     * 0x5652D0 returns -7 (see boot_reconstruction_status.md, 2026-06-13).
     * XPci_SelfTest() has no hardware access and always returns XST_SUCCESS.
     * SiI3512 SATA stub still deferred. */
    {
        DeviceState  *pci_dev = qdev_new("xlnx.opb-pci-host");
        SysBusDevice *pci_sbd = SYS_BUS_DEVICE(pci_dev);
        sysbus_realize_and_unref(pci_sbd, &error_fatal);
        /* Do NOT map the main mmio at 0xe1200000 — that address is the XIntc
         * (corrected 2026-06-21).  The real XPci base is 0xb2600000, which the
         * model already covers via its internal cfg_alias (mapped in realize).
         * CAR/CDR at 0xb260010C/0x110 resolve through that alias. */
    }

    /* NOTE: 0xB2600000 is the XPci CAR/CDR config-cycle port (handled by the
     * xlnx.opb-pci-host cfg_alias above), NOT I2C.  The real XIic (I²C) base is
     * 0xe0800000 (corrected 2026-06-21 from XIic_LookupConfig; that address was
     * previously mis-assigned to the XIntc).  Stub it so the firmware's IIC
     * accesses (sensor/EEPROM/temp) land on a defined region instead of the XIntc. */
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
        install_spy_mr(sysmem, nor, NOR_FLASH_BASE, NOR_FLASH_SIZE,
                        R1MX_DEV_ROM, "nor-flash");
    }
    {
        MemoryRegion *rom = g_new(MemoryRegion, 1);
        memory_region_init_io(rom, NULL, &nor_flash_ops, NULL,
                              "boot-rom", BOOT_ROM_SIZE);
        memory_region_add_subregion(sysmem, BOOT_ROM_BASE, rom);
        install_spy_mr(sysmem, rom, BOOT_ROM_BASE, BOOT_ROM_SIZE,
                        R1MX_DEV_ROM, "boot-rom");
    }

    /* --- ATA/SATA host adapter — empty-bay model (PROTOTYPE) -------------
     * Overlay the IDE task-file registers at the bare legacy ports the firmware
     * polls: command block 0x1F0-0x1F7 (Data..Status) and control block 0x3F6
     * (DevControl/AltStatus).  High priority so these byte ranges shadow the RAM
     * underneath (the low exception-vector page); the rest of the page stays RAM.
     * Reads return 0xFF (floating bus = no media) so the firmware's tick-bounded
     * reset/probe times out and reports "no drive", letting boot proceed past
     * ataPiWait.  See ata_empty_ops above and plans/ata_live_hw_read.md. */
    {
        MemoryRegion *ata_cmd  = g_new(MemoryRegion, 1);
        MemoryRegion *ata_ctrl = g_new(MemoryRegion, 1);
        memory_region_init_io(ata_cmd, NULL, &ata_empty_ops, NULL,
                              "r1mx.ata-cmd", 0x8);   /* 0x1F0-0x1F7 */
        memory_region_init_io(ata_ctrl, NULL, &ata_empty_ops, NULL,
                              "r1mx.ata-ctrl", 0x2);  /* 0x3F6-0x3F7 */
        memory_region_add_subregion_overlap(sysmem, 0x1F0, ata_cmd,  1000);
        memory_region_add_subregion_overlap(sysmem, 0x3F6, ata_ctrl, 1000);
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

    /* --- Activity broker (port 17187) ------------------------------------ */
    activity_broker_init(&g_activity_broker);
    if (g_activity_broker.listen_fd >= 0) {
        fprintf(stderr,
                "R1MX activity monitor: listening on TCP localhost:%d\n"
                "  start GUI: python3 -m toolkit.gui.emulator\n",
                ACTIVITY_TCP_PORT);
    }

    /* --- Block-device activity sampler (SD card + SSD) ------------------- */
    block_sampler_init();

    (void)env; /* suppress unused-variable warning if no further env use */
}

/* ---------------------------------------------------------------------------
 * Machine class
 * --------------------------------------------------------------------------- */

static bool r1mx_get_activity_samplers(Object *obj, Error **errp)
{
    return R1MX_MACHINE(obj)->activity_samplers;
}

static void r1mx_set_activity_samplers(Object *obj, bool value, Error **errp)
{
    R1MX_MACHINE(obj)->activity_samplers = value;
}

static void r1mx_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    object_class_property_add_bool(oc, "activity-samplers",
                                   r1mx_get_activity_samplers,
                                   r1mx_set_activity_samplers);
    object_class_property_set_description(oc, "activity-samplers",
        "Enable periodic CPU-PC and block-device activity samplers "
        "(adds ~500 µs virtual timer overhead; off by default)");

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
