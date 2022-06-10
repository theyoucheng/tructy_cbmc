/*
 * Copyright (c) 2012-2015 Travis Geiselbrecht
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <assert.h>
#include <bits.h>
#include <err.h>
#include <sys/types.h>
#include <debug.h>
#include <dev/interrupt/arm_gic.h>
#include <reg.h>
#include <kernel/thread.h>
#include <kernel/debug.h>
#include <kernel/vm.h>
#include <lk/init.h>
#include <lk/macros.h>
#include <platform/interrupts.h>
#include <arch/ops.h>
#include <platform/gic.h>
#include <trace.h>
#if WITH_LIB_SM
#include <lib/sm.h>
#include <lib/sm/sm_err.h>
#endif

#include "arm_gic_common.h"

#if GIC_VERSION > 2
#include "gic_v3.h"
#endif

#define LOCAL_TRACE 0

#if ARCH_ARM
#define iframe arm_iframe
#define IFRAME_PC(frame) ((frame)->pc)
#endif
#if ARCH_ARM64
#define iframe arm64_iframe_short
#define IFRAME_PC(frame) ((frame)->elr)
#endif

void platform_fiq(struct iframe *frame);
static status_t arm_gic_set_secure_locked(u_int irq, bool secure);
static void gic_set_enable(uint vector, bool enable);
static void arm_gic_init_hw(void);

static spin_lock_t gicd_lock;
#if WITH_LIB_SM
#define GICD_LOCK_FLAGS SPIN_LOCK_FLAG_IRQ_FIQ
#else
#define GICD_LOCK_FLAGS SPIN_LOCK_FLAG_INTERRUPTS
#endif
#define GIC_MAX_PER_CPU_INT 32
#define GIC_MAX_SGI_INT 16

#if ARM_GIC_USE_DOORBELL_NS_IRQ
static bool doorbell_enabled;
#endif

struct arm_gic arm_gics[NUM_ARM_GICS];

#if WITH_LIB_SM
static bool arm_gic_non_secure_interrupts_frozen;

static bool arm_gic_interrupt_change_allowed(int irq)
{
    if (!arm_gic_non_secure_interrupts_frozen)
        return true;

    TRACEF("change to interrupt %d ignored after booting ns\n", irq);
    return false;
}

static void suspend_resume_fiq(bool resume_gicc, bool resume_gicd);
#else
static bool arm_gic_interrupt_change_allowed(int irq)
{
    return true;
}

static void suspend_resume_fiq(bool resume_gicc, bool resume_gicd)
{
}
#endif

struct int_handler_struct {
    int_handler handler;
    void *arg;
};

static struct int_handler_struct int_handler_table_per_cpu[GIC_MAX_PER_CPU_INT][SMP_MAX_CPUS];
static struct int_handler_struct int_handler_table_shared[MAX_INT-GIC_MAX_PER_CPU_INT];

static struct int_handler_struct *get_int_handler(unsigned int vector, uint cpu)
{
    if (vector < GIC_MAX_PER_CPU_INT)
        return &int_handler_table_per_cpu[vector][cpu];
    else
        return &int_handler_table_shared[vector - GIC_MAX_PER_CPU_INT];
}

#if ARM_GIC_USE_DOORBELL_NS_IRQ
static status_t arm_gic_set_priority_locked(u_int irq, uint8_t priority);
#endif

void register_int_handler(unsigned int vector, int_handler handler, void *arg)
{
    struct int_handler_struct *h;
    uint cpu = arch_curr_cpu_num();

    spin_lock_saved_state_t state;

    if (vector >= MAX_INT)
        panic("register_int_handler: vector out of range %d\n", vector);

    spin_lock_save(&gicd_lock, &state, GICD_LOCK_FLAGS);

    if (arm_gic_interrupt_change_allowed(vector)) {
#if GIC_VERSION > 2
        arm_gicv3_configure_irq_locked(cpu, vector);
#endif
        h = get_int_handler(vector, cpu);
        h->handler = handler;
        h->arg = arg;
#if ARM_GIC_USE_DOORBELL_NS_IRQ
        /*
         * Use lowest priority Linux does not mask to allow masking the entire
         * group while still allowing other interrupts to be delivered.
         */
        arm_gic_set_priority_locked(vector, 0xf7);
#endif

        /*
         * For GICv3, SGIs are maskable, and on GICv2, whether they are
         * maskable is implementation defined. As a result, the caller cannot
         * rely on them being maskable, so we enable all registered SGIs as if
         * they were non-maskable.
         */
        if (vector < GIC_MAX_SGI_INT) {
            gic_set_enable(vector, true);
        }
    }

    spin_unlock_restore(&gicd_lock, state, GICD_LOCK_FLAGS);
}

#define GIC_REG_COUNT(bit_per_reg) DIV_ROUND_UP(MAX_INT, (bit_per_reg))
#define DEFINE_GIC_SHADOW_REG(name, bit_per_reg, init_val, init_from) \
    uint32_t (name)[GIC_REG_COUNT(bit_per_reg)] = { \
        [(init_from / bit_per_reg) ... \
         (GIC_REG_COUNT(bit_per_reg) - 1)] = (init_val) \
    }

#if WITH_LIB_SM
static DEFINE_GIC_SHADOW_REG(gicd_igroupr, 32, ~0U, 0);
#endif
static DEFINE_GIC_SHADOW_REG(gicd_itargetsr, 4, 0x01010101, 32);

static void gic_set_enable(uint vector, bool enable)
{
    int reg = vector / 32;
    uint32_t mask = 1ULL << (vector % 32);

#if GIC_VERSION > 2
    if (reg == 0) {
        uint32_t cpu = arch_curr_cpu_num();

        /* On GICv3/v4 these are on GICR */
        if (enable)
            GICRREG_WRITE(0, cpu, GICR_ISENABLER0, mask);
        else
            GICRREG_WRITE(0, cpu, GICR_ICENABLER0, mask);
        return;
    }
#endif
    if (enable)
        GICDREG_WRITE(0, GICD_ISENABLER(reg), mask);
    else
        GICDREG_WRITE(0, GICD_ICENABLER(reg), mask);
}

static void arm_gic_init_percpu(uint level)
{
#if GIC_VERSION > 2
    /* GICv3/v4 */
    arm_gicv3_init_percpu();
#else
    /* GICv2 */
#if WITH_LIB_SM
    GICCREG_WRITE(0, GICC_CTLR, 0xb); // enable GIC0 and select fiq mode for secure
    GICDREG_WRITE(0, GICD_IGROUPR(0), ~0U); /* GICD_IGROUPR0 is banked */
#else
    GICCREG_WRITE(0, GICC_CTLR, 1); // enable GIC0
#endif
    GICCREG_WRITE(0, GICC_PMR, 0xFF); // unmask interrupts at all priority levels
#endif /* GIC_VERSION > 2 */
}

LK_INIT_HOOK_FLAGS(arm_gic_init_percpu,
                   arm_gic_init_percpu,
                   LK_INIT_LEVEL_PLATFORM_EARLY, LK_INIT_FLAG_SECONDARY_CPUS);

static void arm_gic_suspend_cpu(uint level)
{
#if GIC_VERSION > 2
    arm_gicv3_suspend_cpu(arch_curr_cpu_num());
#endif
    suspend_resume_fiq(false, false);
}

LK_INIT_HOOK_FLAGS(arm_gic_suspend_cpu, arm_gic_suspend_cpu,
                   LK_INIT_LEVEL_PLATFORM, LK_INIT_FLAG_CPU_OFF);

static void arm_gic_resume_cpu(uint level)
{
    spin_lock_saved_state_t state;
    bool resume_gicd = false;

    spin_lock_save(&gicd_lock, &state, GICD_LOCK_FLAGS);

#if GIC_VERSION > 2
    if (!(GICDREG_READ(0, GICD_CTLR) & 5)) {
#else
    if (!(GICDREG_READ(0, GICD_CTLR) & 1)) {
#endif
        dprintf(SPEW, "%s: distibutor is off, calling arm_gic_init instead\n", __func__);
        arm_gic_init_hw();
        resume_gicd = true;
    } else {
        arm_gic_init_percpu(0);
    }

#if GIC_VERSION > 2
    {
        uint cpu = arch_curr_cpu_num();
        uint max_irq = resume_gicd ? MAX_INT : GIC_MAX_PER_CPU_INT;

        for (uint v = 0; v < max_irq; v++) {
            struct int_handler_struct *h = get_int_handler(v, cpu);
            if (h->handler) {
                arm_gicv3_configure_irq_locked(cpu, v);
            }
        }
        arm_gicv3_resume_cpu_locked(cpu, resume_gicd);
    }
#endif
    spin_unlock_restore(&gicd_lock, state, GICD_LOCK_FLAGS);
    suspend_resume_fiq(false, resume_gicd);
}

LK_INIT_HOOK_FLAGS(arm_gic_resume_cpu, arm_gic_resume_cpu,
                   LK_INIT_LEVEL_PLATFORM, LK_INIT_FLAG_CPU_RESUME);

static int arm_gic_max_cpu(void)
{
    return (GICDREG_READ(0, GICD_TYPER) >> 5) & 0x7;
}

static void arm_gic_init_hw(void)
{
#if GIC_VERSION > 2
    /* GICv3/v4 */
    arm_gicv3_init();
#else
    int i;

    for (i = 0; i < MAX_INT; i+= 32) {
        GICDREG_WRITE(0, GICD_ICENABLER(i / 32), ~0U);
        GICDREG_WRITE(0, GICD_ICPENDR(i / 32), ~0U);
    }

    if (arm_gic_max_cpu() > 0) {
        /* Set external interrupts to target cpu 0 */
        for (i = 32; i < MAX_INT; i += 4) {
            GICDREG_WRITE(0, GICD_ITARGETSR(i / 4), gicd_itargetsr[i / 4]);
        }
    }

    GICDREG_WRITE(0, GICD_CTLR, 1); // enable GIC0
#if WITH_LIB_SM
    GICDREG_WRITE(0, GICD_CTLR, 3); // enable GIC0 ns interrupts
    /*
     * Iterate through all IRQs and set them to non-secure
     * mode. This will allow the non-secure side to handle
     * all the interrupts we don't explicitly claim.
     */
    for (i = 32; i < MAX_INT; i += 32) {
        u_int reg = i / 32;
        GICDREG_WRITE(0, GICD_IGROUPR(reg), gicd_igroupr[reg]);
    }
#endif
#endif /* GIC_VERSION > 2 */
    arm_gic_init_percpu(0);
}

void arm_gic_init(void) {
#ifdef GICBASE
    arm_gics[0].gicd_vaddr = GICBASE(0) + GICD_OFFSET;
    arm_gics[0].gicd_size = GICD_MIN_SIZE;
#if GIC_VERSION > 2
    arm_gics[0].gicr_vaddr = GICBASE(0) + GICR_OFFSET;
    arm_gics[0].gicr_size = GICR_CPU_OFFSET(SMP_MAX_CPUS - 1) + GICR_MIN_SIZE;
#else /* GIC_VERSION > 2 */
    arm_gics[0].gicc_vaddr = GICBASE(0) + GICC_OFFSET;
    arm_gics[0].gicc_size = GICC_MIN_SIZE;
#endif /* GIC_VERSION > 2 */
#else
    /* Platforms should define GICBASE if they want to call this */
    panic("%s: GICBASE not defined\n", __func__);
#endif /* GICBASE */

    arm_gic_init_hw();
}

static void arm_map_regs(const char* name,
                         vaddr_t* vaddr,
                         paddr_t paddr,
                         size_t size) {
    status_t ret;
    void* vaddrp = (void*)vaddr;

    if (!size) {
        return;
    }

    ret = vmm_alloc_physical(vmm_get_kernel_aspace(), "gic", size, &vaddrp, 0,
                             paddr, 0, ARCH_MMU_FLAG_UNCACHED_DEVICE);
    if (ret) {
        panic("%s: failed %d\n", __func__, ret);
    }

    *vaddr = (vaddr_t)vaddrp;
}

void arm_gic_init_map(struct arm_gic_init_info* init_info)
{
    if (init_info->gicd_size < GICD_MIN_SIZE) {
        panic("%s: gicd mapping too small %zu\n", __func__,
              init_info->gicd_size);
    }
    arm_map_regs("gicd", &arm_gics[0].gicd_vaddr, init_info->gicd_paddr,
                 init_info->gicd_size);
    arm_gics[0].gicd_size = init_info->gicd_size;

#if GIC_VERSION > 2
    if (init_info->gicr_size < GICR_CPU_OFFSET(SMP_MAX_CPUS - 1) + GICR_MIN_SIZE) {
        panic("%s: gicr mapping too small %zu\n", __func__,
              init_info->gicr_size);
    }
    arm_map_regs("gicr", &arm_gics[0].gicr_vaddr, init_info->gicr_paddr,
                 init_info->gicr_size);
    arm_gics[0].gicr_size = init_info->gicr_size;
#else /* GIC_VERSION > 2 */
    if (init_info->gicc_size < GICC_MIN_SIZE) {
        panic("%s: gicc mapping too small %zu\n", __func__,
              init_info->gicc_size);
    }
    arm_map_regs("gicc", &arm_gics[0].gicc_vaddr, init_info->gicc_paddr,
                 init_info->gicc_size);
    arm_gics[0].gicc_size = init_info->gicc_size;
#endif /* GIC_VERSION > 2 */

    arm_gic_init_hw();
}

static status_t arm_gic_set_secure_locked(u_int irq, bool secure)
{
#if WITH_LIB_SM
    int reg = irq / 32;
    uint32_t mask = 1ULL << (irq % 32);

    if (irq >= MAX_INT)
        return ERR_INVALID_ARGS;

    if (secure)
        GICDREG_WRITE(0, GICD_IGROUPR(reg), (gicd_igroupr[reg] &= ~mask));
    else
        GICDREG_WRITE(0, GICD_IGROUPR(reg), (gicd_igroupr[reg] |= mask));
    LTRACEF("irq %d, secure %d, GICD_IGROUP%d = %x\n",
            irq, secure, reg, GICDREG_READ(0, GICD_IGROUPR(reg)));
#endif
    return NO_ERROR;
}

static status_t arm_gic_set_target_locked(u_int irq, u_int cpu_mask, u_int enable_mask)
{
    u_int reg = irq / 4;
    u_int shift = 8 * (irq % 4);
    u_int old_val;
    u_int new_val;

    cpu_mask = (cpu_mask & 0xff) << shift;
    enable_mask = (enable_mask << shift) & cpu_mask;

    old_val = GICDREG_READ(0, GICD_ITARGETSR(reg));
    new_val = (gicd_itargetsr[reg] & ~cpu_mask) | enable_mask;
    GICDREG_WRITE(0, GICD_ITARGETSR(reg), (gicd_itargetsr[reg] = new_val));
    LTRACEF("irq %i, GICD_ITARGETSR%d %x => %x (got %x)\n",
            irq, reg, old_val, new_val, GICDREG_READ(0, GICD_ITARGETSR(reg)));

    return NO_ERROR;
}

static status_t arm_gic_get_priority(u_int irq)
{
    u_int reg = irq / 4;
    u_int shift = 8 * (irq % 4);
    return (GICDREG_READ(0, GICD_IPRIORITYR(reg)) >> shift) & 0xff;
}

static status_t arm_gic_set_priority_locked(u_int irq, uint8_t priority)
{
    u_int reg = irq / 4;
    u_int shift = 8 * (irq % 4);
    u_int mask = 0xffU << shift;
    uint32_t regval;

#if GIC_VERSION > 2
    if (irq < 32) {
        uint cpu = arch_curr_cpu_num();

        /* On GICv3 IPRIORITY registers are on redistributor */
        regval = GICRREG_READ(0, cpu, GICR_IPRIORITYR(reg));
        LTRACEF("irq %i, cpu %d: old GICR_IPRIORITYR%d = %x\n", irq, cpu, reg,
                regval);
        regval = (regval & ~mask) | ((uint32_t)priority << shift);
        GICRREG_WRITE(0, cpu, GICR_IPRIORITYR(reg), regval);
        LTRACEF("irq %i, cpu %d, new GICD_IPRIORITYR%d = %x, req %x\n",
                irq, cpu, reg, GICDREG_READ(0, GICD_IPRIORITYR(reg)), regval);
        return 0;
    }
#endif

    regval = GICDREG_READ(0, GICD_IPRIORITYR(reg));
    LTRACEF("irq %i, old GICD_IPRIORITYR%d = %x\n", irq, reg, regval);
    regval = (regval & ~mask) | ((uint32_t)priority << shift);
    GICDREG_WRITE(0, GICD_IPRIORITYR(reg), regval);
    LTRACEF("irq %i, new GICD_IPRIORITYR%d = %x, req %x\n",
            irq, reg, GICDREG_READ(0, GICD_IPRIORITYR(reg)), regval);

    return 0;
}

status_t arm_gic_sgi(u_int irq, u_int flags, u_int cpu_mask)
{
    if (irq >= 16) {
        return ERR_INVALID_ARGS;
    }

#if GIC_VERSION > 2
    for (size_t cpu = 0; cpu < SMP_MAX_CPUS; cpu++) {
        if (!((cpu_mask >> cpu) & 1)) {
            continue;
        }

        uint64_t val = arm_gicv3_sgir_val(irq, cpu);

        GICCREG_WRITE(0, GICC_PRIMARY_SGIR, val);
    }

#else /* else GIC_VERSION > 2 */

    u_int val =
        ((flags & ARM_GIC_SGI_FLAG_TARGET_FILTER_MASK) << 24) |
        ((cpu_mask & 0xff) << 16) |
        ((flags & ARM_GIC_SGI_FLAG_NS) ? (1U << 15) : 0) |
        (irq & 0xf);

    LTRACEF("GICD_SGIR: %x\n", val);

    GICDREG_WRITE(0, GICD_SGIR, val);

#endif /* else GIC_VERSION > 2 */

    return NO_ERROR;
}

status_t mask_interrupt(unsigned int vector)
{
    if (vector >= MAX_INT)
        return ERR_INVALID_ARGS;

    if (arm_gic_interrupt_change_allowed(vector))
        gic_set_enable(vector, false);

    return NO_ERROR;
}

status_t unmask_interrupt(unsigned int vector)
{
    if (vector >= MAX_INT)
        return ERR_INVALID_ARGS;

    if (arm_gic_interrupt_change_allowed(vector))
        gic_set_enable(vector, true);

    return NO_ERROR;
}

static
enum handler_return __platform_irq(struct iframe *frame)
{
    // get the current vector
    uint32_t iar = GICCREG_READ(0, GICC_PRIMARY_IAR);
    unsigned int vector = iar & 0x3ff;

    if (vector >= 0x3fe) {
#if WITH_LIB_SM && ARM_GIC_USE_DOORBELL_NS_IRQ
        // spurious or non-secure interrupt
        return sm_handle_irq();
#else
        // spurious
        return INT_NO_RESCHEDULE;
#endif
    }

    THREAD_STATS_INC(interrupts);
    KEVLOG_IRQ_ENTER(vector);

    uint cpu = arch_curr_cpu_num();

    LTRACEF_LEVEL(2, "iar 0x%x cpu %u currthread %p vector %d pc 0x%lx\n", iar, cpu,
                  get_current_thread(), vector, (uintptr_t)IFRAME_PC(frame));

    // deliver the interrupt
    enum handler_return ret;

    ret = INT_NO_RESCHEDULE;
    struct int_handler_struct *handler = get_int_handler(vector, cpu);
    if (handler->handler)
        ret = handler->handler(handler->arg);

    GICCREG_WRITE(0, GICC_PRIMARY_EOIR, iar);

    LTRACEF_LEVEL(2, "cpu %u exit %d\n", cpu, ret);

    KEVLOG_IRQ_EXIT(vector);

    return ret;
}

enum handler_return platform_irq(struct iframe *frame)
{
#if WITH_LIB_SM && !ARM_GIC_USE_DOORBELL_NS_IRQ
    uint32_t ahppir = GICCREG_READ(0, GICC_PRIMARY_HPPIR);
    uint32_t pending_irq = ahppir & 0x3ff;
    struct int_handler_struct *h;
    uint cpu = arch_curr_cpu_num();

#if ARM_MERGE_FIQ_IRQ
    {
        uint32_t hppir = GICCREG_READ(0, GICC_HPPIR);
        uint32_t pending_fiq = hppir & 0x3ff;
        if (pending_fiq < MAX_INT) {
            platform_fiq(frame);
            return INT_NO_RESCHEDULE;
        }
    }
#endif

    LTRACEF("ahppir %d\n", ahppir);
    if (pending_irq < MAX_INT && get_int_handler(pending_irq, cpu)->handler) {
        enum handler_return ret = 0;
        uint32_t irq;
        uint8_t old_priority;
        spin_lock_saved_state_t state;

        spin_lock_save(&gicd_lock, &state, GICD_LOCK_FLAGS);

        /* Temporarily raise the priority of the interrupt we want to
         * handle so another interrupt does not take its place before
         * we can acknowledge it.
         */
        old_priority = arm_gic_get_priority(pending_irq);
        arm_gic_set_priority_locked(pending_irq, 0);
        DSB;
        irq = GICCREG_READ(0, GICC_PRIMARY_IAR) & 0x3ff;
        arm_gic_set_priority_locked(pending_irq, old_priority);

        spin_unlock_restore(&gicd_lock, state, GICD_LOCK_FLAGS);

        LTRACEF("irq %d\n", irq);
        if (irq < MAX_INT && (h = get_int_handler(pending_irq, cpu))->handler)
            ret = h->handler(h->arg);
        else
            TRACEF("unexpected irq %d != %d may get lost\n", irq, pending_irq);
        GICCREG_WRITE(0, GICC_PRIMARY_EOIR, irq);
        return ret;
    }
    return sm_handle_irq();
#else
    return __platform_irq(frame);
#endif
}

void platform_fiq(struct iframe *frame)
{
#if WITH_LIB_SM
    sm_handle_fiq();
#else
    PANIC_UNIMPLEMENTED;
#endif
}

#if WITH_LIB_SM
static status_t arm_gic_get_next_irq_locked(u_int min_irq, uint type)
{
#if ARM_GIC_USE_DOORBELL_NS_IRQ
    if (type == TRUSTY_IRQ_TYPE_DOORBELL && min_irq <= ARM_GIC_DOORBELL_IRQ) {
        doorbell_enabled = true;
        return ARM_GIC_DOORBELL_IRQ;
    }
#else
    u_int irq;
    u_int max_irq = type == TRUSTY_IRQ_TYPE_PER_CPU ? GIC_MAX_PER_CPU_INT :
                    type == TRUSTY_IRQ_TYPE_NORMAL ? MAX_INT : 0;
    uint cpu = arch_curr_cpu_num();

    if (type == TRUSTY_IRQ_TYPE_NORMAL && min_irq < GIC_MAX_PER_CPU_INT)
        min_irq = GIC_MAX_PER_CPU_INT;

    for (irq = min_irq; irq < max_irq; irq++)
        if (get_int_handler(irq, cpu)->handler)
            return irq;
#endif

    return SM_ERR_END_OF_INPUT;
}

long smc_intc_get_next_irq(struct smc32_args *args)
{
    status_t ret;
    spin_lock_saved_state_t state;

    spin_lock_save(&gicd_lock, &state, GICD_LOCK_FLAGS);

#if !ARM_GIC_USE_DOORBELL_NS_IRQ
    arm_gic_non_secure_interrupts_frozen = true;
#endif
    ret = arm_gic_get_next_irq_locked(args->params[0], args->params[1]);
    LTRACEF("min_irq %d, per_cpu %d, ret %d\n",
            args->params[0], args->params[1], ret);

    spin_unlock_restore(&gicd_lock, state, GICD_LOCK_FLAGS);

    return ret;
}

static u_long enabled_fiq_mask[BITMAP_NUM_WORDS(MAX_INT)];

static void bitmap_update_locked(u_long *bitmap, u_int bit, bool set)
{
    u_long mask = 1UL << BITMAP_BIT_IN_WORD(bit);

    bitmap += BITMAP_WORD(bit);
    if (set)
        *bitmap |= mask;
    else
        *bitmap &= ~mask;
}

long smc_intc_request_fiq(struct smc32_args *args)
{
    u_int fiq = args->params[0];
    bool enable = args->params[1];
    spin_lock_saved_state_t state;

    dprintf(SPEW, "%s: fiq %d, enable %d\n", __func__, fiq, enable);
    spin_lock_save(&gicd_lock, &state, GICD_LOCK_FLAGS);

    arm_gic_set_secure_locked(fiq, true);
    arm_gic_set_target_locked(fiq, ~0U, ~0U);
    arm_gic_set_priority_locked(fiq, 0);

    gic_set_enable(fiq, enable);
    bitmap_update_locked(enabled_fiq_mask, fiq, enable);

    dprintf(SPEW, "%s: fiq %d, enable %d done\n", __func__, fiq, enable);

    spin_unlock_restore(&gicd_lock, state, GICD_LOCK_FLAGS);

    return NO_ERROR;
}

long smc_intc_fiq_resume(struct smc32_args *args)
{
    suspend_resume_fiq(true, false);

    return 0;
}

static u_int current_fiq[8] = { 0x3ff, 0x3ff, 0x3ff, 0x3ff, 0x3ff, 0x3ff, 0x3ff, 0x3ff };

static bool update_fiq_targets(u_int cpu, bool enable, u_int triggered_fiq, bool resume_gicd)
{
    u_int i, j;
    u_long mask;
    u_int fiq;
    bool smp = arm_gic_max_cpu() > 0;
    bool ret = false;

    spin_lock(&gicd_lock); /* IRQs and FIQs are already masked */
    for (i = 0; i < BITMAP_NUM_WORDS(MAX_INT); i++) {
        mask = enabled_fiq_mask[i];
        while (mask) {
            j = _ffz(~mask);
            mask &= ~(1UL << j);
            fiq = i * BITMAP_BITS_PER_WORD + j;
            if (fiq == triggered_fiq)
                ret = true;
            LTRACEF("cpu %d, irq %i, enable %d\n", cpu, fiq, enable);
            if (smp)
                arm_gic_set_target_locked(fiq, 1U << cpu, enable ? ~0U : 0);
            if (!smp || resume_gicd)
                gic_set_enable(fiq, enable || smp);
        }
    }
    spin_unlock(&gicd_lock);
    return ret;
}

static void suspend_resume_fiq(bool resume_gicc, bool resume_gicd)
{
    u_int cpu = arch_curr_cpu_num();

    ASSERT(cpu < 8);

    update_fiq_targets(cpu, resume_gicc, UINT_MAX, resume_gicd);
}

void sm_intc_enable_interrupts(void)
{
#if ARM_GIC_USE_DOORBELL_NS_IRQ
    GICCREG_WRITE(0, icc_igrpen1_el1, 1); /* Enable secure Group 1 */
    DSB;
#endif
}

status_t sm_intc_fiq_enter(void)
{
    u_int cpu = arch_curr_cpu_num();
#if GIC_VERSION > 2
    u_int irq = GICCREG_READ(0, icc_iar0_el1) & 0x3ff;
#else
    u_int irq = GICCREG_READ(0, GICC_IAR) & 0x3ff;
#endif
    bool fiq_enabled;

    ASSERT(cpu < 8);

    LTRACEF("cpu %d, irq %i\n", cpu, irq);

    if (irq >= 1020) {
#if ARM_GIC_USE_DOORBELL_NS_IRQ
        uint cpu = arch_curr_cpu_num();
        uint64_t val = arm_gicv3_sgir_val(ARM_GIC_DOORBELL_IRQ, cpu);

        GICCREG_WRITE(0, icc_igrpen1_el1, 0); /* Disable secure Group 1 */
        DSB;

        if (doorbell_enabled) {
            LTRACEF("GICD_SGIR: %llx\n", val);
            GICCREG_WRITE(0, icc_asgi1r_el1, val);
        }
#else
        LTRACEF("spurious fiq: cpu %d, old %d, new %d\n", cpu, current_fiq[cpu], irq);
#endif
        return ERR_NO_MSG;
    }

    fiq_enabled = update_fiq_targets(cpu, false, irq, false);
#if GIC_VERSION > 2
    GICCREG_WRITE(0, icc_eoir0_el1, irq);
#else
    GICCREG_WRITE(0, GICC_EOIR, irq);
#endif

    if (current_fiq[cpu] != 0x3ff) {
        dprintf(INFO, "more than one fiq active: cpu %d, old %d, new %d\n", cpu, current_fiq[cpu], irq);
        return ERR_ALREADY_STARTED;
    }

    if (!fiq_enabled) {
        dprintf(INFO, "got disabled fiq: cpu %d, new %d\n", cpu, irq);
        return ERR_NOT_READY;
    }

    current_fiq[cpu] = irq;

    return 0;
}

void sm_intc_fiq_exit(void)
{
    u_int cpu = arch_curr_cpu_num();

    ASSERT(cpu < 8);

    LTRACEF("cpu %d, irq %i\n", cpu, current_fiq[cpu]);
    if (current_fiq[cpu] == 0x3ff) {
        dprintf(INFO, "%s: no fiq active, cpu %d\n", __func__, cpu);
        return;
    }
    update_fiq_targets(cpu, true, current_fiq[cpu], false);
    current_fiq[cpu] = 0x3ff;
}
#endif
