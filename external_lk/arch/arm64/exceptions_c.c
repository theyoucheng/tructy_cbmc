/*
 * Copyright (c) 2014 Travis Geiselbrecht
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
#include <bits.h>
#include <ctype.h>
#include <debug.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <arch/arch_ops.h>
#include <arch/arm64.h>
#include <arch/mmu.h>
#include <arch/safecopy.h>
#include <kernel/vm.h>
#include <lib/trusty/trusty_app.h>

#define SHUTDOWN_ON_FATAL 1

/**
 * struct fault_handler_table_entry - Fault handler table entry.
 * @pc: Address of the faulting instruction.
 * @fault_handler: Address of the corresponding fault handler.
 *
 * Both addresses are position-relative, i.e., each field contains the offset
 * from the field itself to its target.
 */
struct fault_handler_table_entry {
    int64_t pc;
    int64_t fault_handler;
};

extern struct fault_handler_table_entry __fault_handler_table_start[];
extern struct fault_handler_table_entry __fault_handler_table_end[];

/**
 * prel_to_abs_u64() - Convert a position-relative value to an absolute.
 * @ptr: Pointer to a 64-bit position-relative value.
 * @result: Pointer to the location for the result.
 *
 * Return: %true in case of success, %false for overflow.
 */
static inline bool prel_to_abs_u64(const int64_t* ptr, uint64_t* result) {
    return !__builtin_add_overflow((uintptr_t)ptr, *ptr, result);
}

static bool check_fault_handler_table(struct arm64_iframe_long *iframe)
{
    struct fault_handler_table_entry *fault_handler;
    for (fault_handler = __fault_handler_table_start;
            fault_handler < __fault_handler_table_end;
            fault_handler++) {
        uint64_t addr;
        if (!prel_to_abs_u64(&fault_handler->pc, &addr)) {
            /* Invalid entry, ignore it */
            continue;
        }
        if (addr == iframe->elr) {
            if (!prel_to_abs_u64(&fault_handler->fault_handler, &addr)) {
                /*
                 * An entry with an invalid handler address. We don't expect
                 * another entry with the same pc, so we break out of
                 * the loop early.
                 */
                return false;
            }

            iframe->elr = addr;
            return true;
        }
    }
    return false;
}

#if TEST_BUILD
static uint64_t wrap_add(uint64_t addr, int offset) {
    uint64_t result;
    __builtin_add_overflow(addr, offset, &result);
    return result;
}

static bool getmeminfo(uint64_t addr, paddr_t *paddr, uint *flags) {
    status_t ret = NO_ERROR;
    vmm_aspace_t *aspace = vaddr_to_aspace((void*)addr);
    if (aspace) {
        ret = arch_mmu_query(&aspace->arch_aspace, addr, paddr, flags);
    }

    if (aspace && ret == NO_ERROR) {
        return true;
    }
    return false;
}

static void printmemattrs(
        const char *prefix, paddr_t start, size_t len, uint flags) {
    printf("%s0x%lx/0x%zx, flags: 0x%02x [ read%s%s%s%s%s%s ]):\n",
            prefix, start, len, flags,
            !(flags & ARCH_MMU_FLAG_PERM_RO) ? " write" : "",
            !(flags & ARCH_MMU_FLAG_PERM_NO_EXECUTE) ? " execute" : "",
            (flags & ARCH_MMU_FLAG_PERM_USER) ? " user" : "",
            (flags & ARCH_MMU_FLAG_NS) ? " nonsecure" : "",
            (flags & ARCH_MMU_FLAG_UNCACHED_DEVICE) ? " device" : "",
            (flags & ARCH_MMU_FLAG_UNCACHED) ? " uncached" : "");
}

static void dump_memory_around_register(const char *name, uint64_t regaddr) {
    uint64_t addr = wrap_add(regaddr, -16);
    uint64_t secondpageaddr;

    uint8_t data[48];

    int page_size = PAGE_SIZE;
    if (is_user_address(addr)) {
        page_size = USER_PAGE_SIZE;
    }
    uint64_t offsetinpage = addr & (page_size - 1);
    uint64_t bytesonfirstpage = page_size - offsetinpage;
    if (bytesonfirstpage > sizeof(data)) {
        bytesonfirstpage = sizeof(data);
    }

    paddr_t paddr1, paddr2;
    uint flags1, flags2;
    bool info1valid =false;
    bool info2valid = false;
    bool read1ok = false;
    bool read2ok = false;

    info1valid = getmeminfo(addr, &paddr1, &flags1);

    if (bytesonfirstpage < sizeof(data)) {
        /* this block spans a page boundary */
        secondpageaddr = wrap_add(addr, bytesonfirstpage);
        info2valid = getmeminfo(secondpageaddr, &paddr2, &flags2);
    }

    if (!info1valid && !info2valid) {
        return;
    }

    if (info1valid &&
            ((flags1 & ARCH_MMU_FLAG_CACHE_MASK) == ARCH_MMU_FLAG_CACHED ||
            (flags1 & ARCH_MMU_FLAG_CACHE_MASK) == ARCH_MMU_FLAG_UNCACHED)) {
        /* this should only fail if the page was remapped after we queried it */
        status_t ret = copy_from_anywhere(data, addr, bytesonfirstpage);
        read1ok = (ret == NO_ERROR);
    }

    if (info2valid &&
            ((flags2 & ARCH_MMU_FLAG_CACHE_MASK) == ARCH_MMU_FLAG_CACHED ||
            (flags2 & ARCH_MMU_FLAG_CACHE_MASK) == ARCH_MMU_FLAG_UNCACHED)) {
        status_t ret = copy_from_anywhere(data + bytesonfirstpage,
                secondpageaddr, sizeof(data) - bytesonfirstpage);
        read2ok = (ret == NO_ERROR);
    }

    printf("\nmemory around %3s (", name);
    if (info1valid) {
        printmemattrs("phys: ", paddr1, bytesonfirstpage, flags1);
    } else {
        printf("phys: <unmapped>/0x%llx):\n", bytesonfirstpage);
    }
    if (bytesonfirstpage < sizeof(data)) {
        if (info2valid) {
            printmemattrs("              and (phys: ",
                   paddr2,
                   sizeof(data) - bytesonfirstpage,
                   flags2);
        } else {
            printf("              and (phys: <unmapped>/0x%llx):\n",
                    sizeof(data) - bytesonfirstpage);
        }
    }

    for (size_t offset = 0; offset < sizeof(data); offset += 16) {
        printf("0x%016llx: ", wrap_add(addr, offset));

        for (int i = 0; i < 16; i++) {
            if (i == 8) {
                printf(" ");
            }
            if ((offset + i < bytesonfirstpage && read1ok) ||
                    (offset + i >= bytesonfirstpage && read2ok)) {
                printf("%02hhx ", data[offset + i]);
            } else {
                printf("-- ");
            }
        }

        printf("|");

        for (int i = 0; i < 16; i++) {
            unsigned char c = data[offset + i];
            printf("%c", ((offset + i < bytesonfirstpage && read1ok) ||
                    (offset + i >= bytesonfirstpage && read2ok)) &&
                    isprint(c) ? c : '.');
        }

        printf("\n");
    }
}

static void dump_memory_around_registers(
        const struct arm64_iframe_long *iframe) {
    char regname[4];
    for (int i = 0; i < 28; i++) {
        snprintf(regname, sizeof(regname), "x%d", i);
        dump_memory_around_register(regname, iframe->r[i]);
    }
    dump_memory_around_register("fp", iframe->fp);
    dump_memory_around_register("lr", iframe->lr);
    dump_memory_around_register("sp", iframe->sp);
    dump_memory_around_register("elr", iframe->elr);
}
#endif

static void dump_iframe(const struct arm64_iframe_long *iframe)
{
    struct thread *thread = get_current_thread();
    printf("thread: %p (%s)\n", thread, thread->name);
    printf("stack   %p-%p\n", thread->stack, thread->stack + thread->stack_size);
    printf("iframe  %p:\n", iframe);
#if TEST_BUILD
    printf("x0  0x%16llx x1  0x%16llx x2  0x%16llx x3  0x%16llx\n", iframe->r[0], iframe->r[1], iframe->r[2], iframe->r[3]);
    printf("x4  0x%16llx x5  0x%16llx x6  0x%16llx x7  0x%16llx\n", iframe->r[4], iframe->r[5], iframe->r[6], iframe->r[7]);
    printf("x8  0x%16llx x9  0x%16llx x10 0x%16llx x11 0x%16llx\n", iframe->r[8], iframe->r[9], iframe->r[10], iframe->r[11]);
    printf("x12 0x%16llx x13 0x%16llx x14 0x%16llx x15 0x%16llx\n", iframe->r[12], iframe->r[13], iframe->r[14], iframe->r[15]);
    printf("x16 0x%16llx x17 0x%16llx x18 0x%16llx x19 0x%16llx\n", iframe->r[16], iframe->r[17], iframe->r[18], iframe->r[19]);
    printf("x20 0x%16llx x21 0x%16llx x22 0x%16llx x23 0x%16llx\n", iframe->r[20], iframe->r[21], iframe->r[22], iframe->r[23]);
    printf("x24 0x%16llx x25 0x%16llx x26 0x%16llx x27 0x%16llx\n", iframe->r[24], iframe->r[25], iframe->r[26], iframe->r[27]);
    printf("x28 0x%16llx fp  0x%16llx lr  0x%16llx sp  0x%16llx\n", iframe->r[28], iframe->fp, iframe->lr, iframe->sp);
    printf("elr 0x%16llx\n", iframe->elr);
    printf("spsr 0x%16llx\n", iframe->spsr);
#endif
}

__WEAK void arm64_syscall(struct arm64_iframe_long *iframe, bool is_64bit)
{
    panic("unhandled syscall vector\n");
}

static void print_fault_code(uint32_t fsc) {
    printf("fault code 0x%x: ", fsc);
    switch (fsc) {
        case 0b000000:
        case 0b000001:
        case 0b000010:
        case 0b000011:
            printf("Address size fault, level %d", fsc & 0x3);
            break;
        case 0b000100:
        case 0b000101:
        case 0b000110:
        case 0b000111:
            printf("Translation fault, level %d", fsc & 0x3);
            break;
        case 0b001001:
        case 0b001010:
        case 0b001011:
            printf("Access flag fault, level %d", fsc & 0x3);
            break;
        case 0b001101:
        case 0b001110:
        case 0b001111:
            printf("Permission fault, level %d", fsc & 0x3);
            break;

        case 0b010000:
            printf("External abort");
            break;

        case 0b010001:
            printf("Tag check fault");
            break;

        case 0b010100:
        case 0b010101:
        case 0b010110:
        case 0b010111:
            printf("External abort on translation table, level %d", fsc & 0x3);
            break;

        case 0b011000:
            printf("Parity or ECC error");
            break;

        case 0b011100:
        case 0b011101:
        case 0b011110:
        case 0b011111:
            printf("Parity or ECC error on translation table, level %d", fsc & 0x3);
            break;

        case 0b100001:
            printf("Alignment fault");
            break;

        case 0b110000:
            printf("TLB conflict abort");
            break;

        case 0b110001:
            printf("Unsupported atomic hardware update fault");
            break;

        case 0b110100:
            printf("Lockdown fault");
            break;

        case 0b110101:
            printf("Unsupported exclusive or atomic access");
            break;

        default:
            printf("Unknown fault");
            break;
    }
    printf("\n");
}

void arm64_sync_exception(struct arm64_iframe_long *iframe, bool from_lower)
{
    uint32_t esr = ARM64_READ_SYSREG(esr_el1);
    uint32_t ec = BITS_SHIFT(esr, 31, 26);
    uint32_t il = BIT_SHIFT(esr, 25);
    uint32_t iss = BITS(esr, 24, 0);
    uintptr_t display_pc = iframe->elr;

    if (from_lower) {
        /*
         * load_bias may intentionally overflow to represent a shift
         * down of the application base address
         */
        __builtin_sub_overflow(display_pc,
                               current_trusty_app()->load_bias,
                               &display_pc);
    }

    switch (ec) {
        case 0b000111: /* floating point */
            arm64_fpu_exception(iframe);
            return;
        case 0b010001: /* syscall from arm32 */
        case 0b010101: /* syscall from arm64 */
#ifdef WITH_LIB_SYSCALL
            arch_enable_fiqs();
            arm64_syscall(iframe, (ec == 0x15) ? true : false);
            arch_disable_fiqs();
            return;
#else
            arm64_syscall(iframe, (ec == 0x15) ? true : false);
            return;
#endif
        case 0b100000: /* instruction abort from lower level */
        case 0b100001: /* instruction abort from same level */
            if (check_fault_handler_table(iframe)) {
                return;
            }
            printf("instruction abort: PC at 0x%llx(0x%lx)\n", iframe->elr,
                   display_pc);
            print_fault_code(BITS(iss, 5, 0));
            break;
        case 0b100100: /* data abort from lower level */
        case 0b100101: { /* data abort from same level */
            if (check_fault_handler_table(iframe)) {
                return;
            }

            /* read the FAR register */
            uint64_t far = ARM64_READ_SYSREG(far_el1);

            /* decode the iss */
            uint32_t dfsc = BITS(iss, 5, 0);
            printf("data fault ");
            if (BIT(iss, 6)) {
                printf("writing to ");
            } else {
                printf("reading from ");
            }
            if (dfsc == 0b010000 && BIT(iss, 10)) {
                printf("unknown address (FAR 0x%llx not valid)", far);
            } else {
                printf("0x%llx", far);
            }
            printf(", PC at 0x%llx(0x%lx)\n", iframe->elr, display_pc);
            if (BIT(iss, 24)) { /* ISV bit */
                printf("Access size: %d bits, sign extension: %s, register: %s%lu, %s acquire release semantics\n",
                        8 << BITS_SHIFT(iss,23,22),
                        BIT_SHIFT(iss,21) ? "yes" : "no",
                        BIT_SHIFT(iss,15) ? "X" : "W",
                        BITS_SHIFT(iss,20,16),
                        BIT_SHIFT(iss,14) ? "" : "no");
            }
            print_fault_code(dfsc);
            break;
        }
        case 0b111100: {
            printf("BRK #0x%04lx instruction: PC at 0x%llx(0x%lx)\n",
                   BITS_SHIFT(iss, 15, 0), iframe->elr, display_pc);
            break;
        }
        default:
            printf("unhandled synchronous exception: PC at 0x%llx(0x%lx)\n",
                   iframe->elr, display_pc);
    }

    /* unhandled exception, die here */
    if (from_lower) {
        printf("app: %s\n", current_trusty_app()->props.app_name);
        printf("load bias: 0x%lx\n", current_trusty_app()->load_bias);
    }
    printf("ESR 0x%x: ec 0x%x, il 0x%x, iss 0x%x\n", esr, ec, il, iss);
    dump_iframe(iframe);
#if TEST_BUILD
    dump_memory_around_registers(iframe);
#endif

    if (from_lower) {
        arch_enable_fiqs();
        arch_enable_ints();
        trusty_app_crash();
    }
    panic("die\n");
}

void arm64_invalid_exception(struct arm64_iframe_long *iframe, unsigned int which)
{
    printf("invalid exception, which 0x%x\n", which);
    dump_iframe(iframe);
#if TEST_BUILD
    dump_memory_around_registers(iframe);
#endif

    panic("die\n");
}
