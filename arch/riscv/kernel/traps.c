// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/kdebug.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/uprobes.h>
#include <asm/uprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/kexec.h>
#include <linux/entry-common.h>

#include <asm/asm-prototypes.h>
#include <asm/bug.h>
#include <asm/cfi.h>
#include <asm/csr.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include <asm/thread_info.h>
#include <asm/vector.h>
#include <asm/irq_stack.h>


#include <linux/random.h>

unsigned long mitigation_fuzzy_timing_SIGILL_cycles = 0;
EXPORT_SYMBOL_GPL(mitigation_fuzzy_timing_SIGILL_cycles);

unsigned long enable_mitigation_emulate_csr = 0;
EXPORT_SYMBOL_GPL(enable_mitigation_emulate_csr);



int show_unhandled_signals = 1;

static DEFINE_SPINLOCK(die_lock);

static void dump_kernel_instr(const char *loglvl, struct pt_regs *regs)
{
	char str[sizeof("0000 ") * 12 + 2 + 1], *p = str;
	const u16 *insns = (u16 *)instruction_pointer(regs);
	long bad;
	u16 val;
	int i;

	for (i = -10; i < 2; i++) {
		bad = get_kernel_nofault(val, &insns[i]);
		if (!bad) {
			p += sprintf(p, i == 0 ? "(%04hx) " : "%04hx ", val);
		} else {
			printk("%sCode: Unable to access instruction at 0x%px.\n",
			       loglvl, &insns[i]);
			return;
		}
	}
	printk("%sCode: %s\n", loglvl, str);
}

void die(struct pt_regs *regs, const char *str)
{
	static int die_counter;
	int ret;
	long cause;
	unsigned long flags;

	oops_enter();

	spin_lock_irqsave(&die_lock, flags);
	console_verbose();
	bust_spinlocks(1);

	pr_emerg("%s [#%d]\n", str, ++die_counter);
	print_modules();
	if (regs) {
		show_regs(regs);
		dump_kernel_instr(KERN_EMERG, regs);
	}

	cause = regs ? regs->cause : -1;
	ret = notify_die(DIE_OOPS, str, regs, 0, cause, SIGSEGV);

	if (kexec_should_crash(current))
		crash_kexec(regs);

	bust_spinlocks(0);
	add_taint(TAINT_DIE, LOCKDEP_NOW_UNRELIABLE);
	spin_unlock_irqrestore(&die_lock, flags);
	oops_exit();

	if (in_interrupt())
		panic("Fatal exception in interrupt");
	if (panic_on_oops)
		panic("Fatal exception");
	if (ret != NOTIFY_STOP)
		make_task_dead(SIGSEGV);
}

void do_trap(struct pt_regs *regs, int signo, int code, unsigned long addr)
{
	struct task_struct *tsk = current;

	if (show_unhandled_signals && unhandled_signal(tsk, signo)
	    && printk_ratelimit()) {
		pr_info("%s[%d]: unhandled signal %d code 0x%x at 0x" REG_FMT,
			tsk->comm, task_pid_nr(tsk), signo, code, addr);
		print_vma_addr(KERN_CONT " in ", instruction_pointer(regs));
		pr_cont("\n");
		__show_regs(regs);
	}

	force_sig_fault(signo, code, (void __user *)addr);
}

static void do_trap_error(struct pt_regs *regs, int signo, int code,
	unsigned long addr, const char *str)
{
	current->thread.bad_cause = regs->cause;

	if (user_mode(regs)) {
		do_trap(regs, signo, code, addr);
	} else {
		if (!fixup_exception(regs))
			die(regs, str);
	}
}

#if defined(CONFIG_XIP_KERNEL) && defined(CONFIG_RISCV_ALTERNATIVE)
#define __trap_section __noinstr_section(".xip.traps")
#else
#define __trap_section noinstr
#endif
#define DO_ERROR_INFO(name, signo, code, str)					\
asmlinkage __visible __trap_section void name(struct pt_regs *regs)		\
{										\
	if (user_mode(regs)) {							\
		irqentry_enter_from_user_mode(regs);				\
		do_trap_error(regs, signo, code, regs->epc, "Oops - " str);	\
		irqentry_exit_to_user_mode(regs);				\
	} else {								\
		irqentry_state_t state = irqentry_nmi_enter(regs);		\
		do_trap_error(regs, signo, code, regs->epc, "Oops - " str);	\
		irqentry_nmi_exit(regs, state);					\
	}									\
}

DO_ERROR_INFO(do_trap_unknown,
	SIGILL, ILL_ILLTRP, "unknown exception");
DO_ERROR_INFO(do_trap_insn_misaligned,
	SIGBUS, BUS_ADRALN, "instruction address misaligned");
DO_ERROR_INFO(do_trap_insn_fault,
	SIGSEGV, SEGV_ACCERR, "instruction access fault");

// Helper to emulate CSR reads like rdcycle, rdtime, rdinstret
static bool emulate_csr_read(struct pt_regs *regs)
{
	// Read user instruction
    u32 insn;
    if (get_user(insn, (u32 __user *)regs->epc)) {
        pr_warn("Failed to read instruction from EPC: 0x%lx\n", regs->epc);
		return false;
    }

    u32 opcode  = insn & 0x7f;
    u32 rd      = (insn >> 7) & 0x1f;
    u32 funct3  = (insn >> 12) & 0x7;
    u32 rs1     = (insn >> 15) & 0x1f;
    u32 csr     = (insn >> 20) & 0xfff;

    pr_info("Fetched instruction: 0x%08x\n", insn);
    pr_info("Opcode: 0x%02x, rd:0x%01x, funct3: 0x%01x, rs1: 0x%01x, csr: 0x%03x\n", opcode, rd, funct3, rs1, csr);

	if (opcode == 0x73 && funct3 == 0x2 && rs1 == 0) {
		unsigned long val = 0;

		// Get specific CSR instruction
		switch (csr) {
			case CSR_CYCLE:
				val = 1234567890; // Set emulated value
				break;
			case CSR_TIME:
				val = 987654321; // Set emulated value
				break;
			case CSR_INSTRET:
				val = 0xDEADBEEF; // Set emulated value
				break;
			default:
				return false;
		}

		// Get target register and write value
		if (rd != 0) {
			switch (rd) {
				case 1: regs->ra = val; break;
				case 2: regs->sp = val; break;
				case 3: regs->gp = val; break;
				case 4: regs->tp = val; break;
				case 5: regs->t0 = val; break;
				case 6: regs->t1 = val; break;
				case 7: regs->t2 = val; break;
				case 8: regs->s0 = val; break;
				case 9: regs->s1 = val; break;
				case 10: regs->a0 = val; break;
				case 11: regs->a1 = val; break;
				case 12: regs->a2 = val; break;
				case 13: regs->a3 = val; break;
				case 14: regs->a4 = val; break;
				case 15: regs->a5 = val; break;
				case 16: regs->a6 = val; break;
				case 17: regs->a7 = val; break;
				case 18: regs->s2 = val; break;
				case 19: regs->s3 = val; break;
				case 20: regs->s4 = val; break;
				case 21: regs->s5 = val; break;
				case 22: regs->s6 = val; break;
				case 23: regs->s7 = val; break;
				case 24: regs->s8 = val; break;
				case 25: regs->s9 = val; break;
				case 26: regs->s10 = val; break;
				case 27: regs->s11 = val; break;
				case 28: regs->t3 = val; break;
				case 29: regs->t4 = val; break;
				case 30: regs->t5 = val; break;
				case 31: regs->t6 = val; break;
				default: break; // rd == 0 (x0), no write
			}
		}

		// Step program counter
		regs->epc += 4;

		pr_info("Emulated CSR 0x%03x => x%d = 0x%lx at EPC=0x%lx\n", csr, rd, val, regs->epc - 4);

		return true;
	}

    return false;
}

asmlinkage __visible __trap_section void do_trap_insn_illegal(struct pt_regs *regs)
{
	bool handled;

	if (user_mode(regs)) {
		irqentry_enter_from_user_mode(regs);

		local_irq_enable();

		handled = riscv_v_first_use_handler(regs);

		if (!handled && enable_mitigation_emulate_csr) { // emulating known CSR reads
			handled = emulate_csr_read(regs);
		}

		local_irq_disable();

		if (!handled) {
			do_trap_error(regs, SIGILL, ILL_ILLOPC, regs->epc,
				      "Oops - illegal instruction");
			
			// RISC-V mitigation: fuzzy timing on SIGILL
			if (mitigation_fuzzy_timing_SIGILL_cycles) {
				u32 delay = get_random_u32_below((u32)mitigation_fuzzy_timing_SIGILL_cycles);
				while (delay--)
					asm volatile ("nop");
			}

		}

		irqentry_exit_to_user_mode(regs);
	} else {
		irqentry_state_t state = irqentry_nmi_enter(regs);

		do_trap_error(regs, SIGILL, ILL_ILLOPC, regs->epc,
			      "Oops - illegal instruction");

		irqentry_nmi_exit(regs, state);
	}
}

DO_ERROR_INFO(do_trap_load_fault,
	SIGSEGV, SEGV_ACCERR, "load access fault");
#ifndef CONFIG_RISCV_M_MODE
DO_ERROR_INFO(do_trap_load_misaligned,
	SIGBUS, BUS_ADRALN, "Oops - load address misaligned");
DO_ERROR_INFO(do_trap_store_misaligned,
	SIGBUS, BUS_ADRALN, "Oops - store (or AMO) address misaligned");
#else
int handle_misaligned_load(struct pt_regs *regs);
int handle_misaligned_store(struct pt_regs *regs);

asmlinkage __visible __trap_section void do_trap_load_misaligned(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		irqentry_enter_from_user_mode(regs);

		if (handle_misaligned_load(regs))
			do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
			      "Oops - load address misaligned");

		irqentry_exit_to_user_mode(regs);
	} else {
		irqentry_state_t state = irqentry_nmi_enter(regs);

		if (handle_misaligned_load(regs))
			do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
			      "Oops - load address misaligned");

		irqentry_nmi_exit(regs, state);
	}
}

asmlinkage __visible __trap_section void do_trap_store_misaligned(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		irqentry_enter_from_user_mode(regs);

		if (handle_misaligned_store(regs))
			do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
				"Oops - store (or AMO) address misaligned");

		irqentry_exit_to_user_mode(regs);
	} else {
		irqentry_state_t state = irqentry_nmi_enter(regs);

		if (handle_misaligned_store(regs))
			do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
				"Oops - store (or AMO) address misaligned");

		irqentry_nmi_exit(regs, state);
	}
}
#endif
DO_ERROR_INFO(do_trap_store_fault,
	SIGSEGV, SEGV_ACCERR, "store (or AMO) access fault");
DO_ERROR_INFO(do_trap_ecall_s,
	SIGILL, ILL_ILLTRP, "environment call from S-mode");
DO_ERROR_INFO(do_trap_ecall_m,
	SIGILL, ILL_ILLTRP, "environment call from M-mode");

static inline unsigned long get_break_insn_length(unsigned long pc)
{
	bug_insn_t insn;

	if (get_kernel_nofault(insn, (bug_insn_t *)pc))
		return 0;

	return GET_INSN_LENGTH(insn);
}

static bool probe_single_step_handler(struct pt_regs *regs)
{
	bool user = user_mode(regs);

	return user ? uprobe_single_step_handler(regs) : kprobe_single_step_handler(regs);
}

static bool probe_breakpoint_handler(struct pt_regs *regs)
{
	bool user = user_mode(regs);

	return user ? uprobe_breakpoint_handler(regs) : kprobe_breakpoint_handler(regs);
}

void handle_break(struct pt_regs *regs)
{
	if (probe_single_step_handler(regs))
		return;

	if (probe_breakpoint_handler(regs))
		return;

	current->thread.bad_cause = regs->cause;

	if (user_mode(regs))
		force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->epc);
#ifdef CONFIG_KGDB
	else if (notify_die(DIE_TRAP, "EBREAK", regs, 0, regs->cause, SIGTRAP)
								== NOTIFY_STOP)
		return;
#endif
	else if (report_bug(regs->epc, regs) == BUG_TRAP_TYPE_WARN ||
		 handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN)
		regs->epc += get_break_insn_length(regs->epc);
	else
		die(regs, "Kernel BUG");
}

asmlinkage __visible __trap_section void do_trap_break(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		irqentry_enter_from_user_mode(regs);

		handle_break(regs);

		irqentry_exit_to_user_mode(regs);
	} else {
		irqentry_state_t state = irqentry_nmi_enter(regs);

		handle_break(regs);

		irqentry_nmi_exit(regs, state);
	}
}

asmlinkage __visible __trap_section void do_trap_ecall_u(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		long syscall = regs->a7;

		regs->epc += 4;
		regs->orig_a0 = regs->a0;

		riscv_v_vstate_discard(regs);

		syscall = syscall_enter_from_user_mode(regs, syscall);

		if (syscall >= 0 && syscall < NR_syscalls)
			syscall_handler(regs, syscall);
		else if (syscall != -1)
			regs->a0 = -ENOSYS;

		syscall_exit_to_user_mode(regs);
	} else {
		irqentry_state_t state = irqentry_nmi_enter(regs);

		do_trap_error(regs, SIGILL, ILL_ILLTRP, regs->epc,
			"Oops - environment call from U-mode");

		irqentry_nmi_exit(regs, state);
	}

}

#ifdef CONFIG_MMU
asmlinkage __visible noinstr void do_page_fault(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);

	handle_page_fault(regs);

	local_irq_disable();

	irqentry_exit(regs, state);
}
#endif

static void noinstr handle_riscv_irq(struct pt_regs *regs)
{
	struct pt_regs *old_regs;

	irq_enter_rcu();
	old_regs = set_irq_regs(regs);
	handle_arch_irq(regs);
	set_irq_regs(old_regs);
	irq_exit_rcu();
}

asmlinkage void noinstr do_irq(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);
#ifdef CONFIG_IRQ_STACKS
	if (on_thread_stack()) {
		ulong *sp = per_cpu(irq_stack_ptr, smp_processor_id())
					+ IRQ_STACK_SIZE/sizeof(ulong);
		__asm__ __volatile(
		"addi	sp, sp, -"RISCV_SZPTR  "\n"
		REG_S"  ra, (sp)		\n"
		"addi	sp, sp, -"RISCV_SZPTR  "\n"
		REG_S"  s0, (sp)		\n"
		"addi	s0, sp, 2*"RISCV_SZPTR "\n"
		"move	sp, %[sp]		\n"
		"move	a0, %[regs]		\n"
		"call	handle_riscv_irq	\n"
		"addi	sp, s0, -2*"RISCV_SZPTR"\n"
		REG_L"  s0, (sp)		\n"
		"addi	sp, sp, "RISCV_SZPTR   "\n"
		REG_L"  ra, (sp)		\n"
		"addi	sp, sp, "RISCV_SZPTR   "\n"
		:
		: [sp] "r" (sp), [regs] "r" (regs)
		: "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
		  "t0", "t1", "t2", "t3", "t4", "t5", "t6",
#ifndef CONFIG_FRAME_POINTER
		  "s0",
#endif
		  "memory");
	} else
#endif
		handle_riscv_irq(regs);

	irqentry_exit(regs, state);
}

#ifdef CONFIG_GENERIC_BUG
int is_valid_bugaddr(unsigned long pc)
{
	bug_insn_t insn;

	if (pc < VMALLOC_START)
		return 0;
	if (get_kernel_nofault(insn, (bug_insn_t *)pc))
		return 0;
	if ((insn & __INSN_LENGTH_MASK) == __INSN_LENGTH_32)
		return (insn == __BUG_INSN_32);
	else
		return ((insn & __COMPRESSED_INSN_MASK) == __BUG_INSN_16);
}
#endif /* CONFIG_GENERIC_BUG */

#ifdef CONFIG_VMAP_STACK
DEFINE_PER_CPU(unsigned long [OVERFLOW_STACK_SIZE/sizeof(long)],
		overflow_stack)__aligned(16);

asmlinkage void handle_bad_stack(struct pt_regs *regs)
{
	unsigned long tsk_stk = (unsigned long)current->stack;
	unsigned long ovf_stk = (unsigned long)this_cpu_ptr(overflow_stack);

	console_verbose();

	pr_emerg("Insufficient stack space to handle exception!\n");
	pr_emerg("Task stack:     [0x%016lx..0x%016lx]\n",
			tsk_stk, tsk_stk + THREAD_SIZE);
	pr_emerg("Overflow stack: [0x%016lx..0x%016lx]\n",
			ovf_stk, ovf_stk + OVERFLOW_STACK_SIZE);

	__show_regs(regs);
	panic("Kernel stack overflow");

	for (;;)
		wait_for_interrupt();
}
#endif
