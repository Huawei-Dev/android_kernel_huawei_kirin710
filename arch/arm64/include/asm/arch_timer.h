/*
 * arch/arm64/include/asm/arch_timer.h
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_ARCH_TIMER_H
#define __ASM_ARCH_TIMER_H

#include <asm/barrier.h>
#include <asm/sysreg.h>

#include <linux/bug.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/types.h>

#include <clocksource/arm_arch_timer.h>

#if IS_ENABLED(CONFIG_ARM_ARCH_TIMER_OOL_WORKAROUND)
extern struct static_key_false arch_timer_read_ool_enabled;
#define needs_unstable_timer_counter_workaround() \
	static_branch_unlikely(&arch_timer_read_ool_enabled)
#else
#define needs_unstable_timer_counter_workaround()  false
#endif

enum arch_timer_erratum_match_type {
	ate_match_dt,
	ate_match_local_cap_id,
};

struct arch_timer_erratum_workaround {
	enum arch_timer_erratum_match_type match_type;
	const void *id;
	const char *desc;
	u32 (*read_cntp_tval_el0)(void);
	u32 (*read_cntv_tval_el0)(void);
	u64 (*read_cntvct_el0)(void);
};

extern const struct arch_timer_erratum_workaround *timer_unstable_counter_workaround;

#define arch_timer_reg_read_stable(reg) 		\
({							\
	u64 _val;					\
	if (needs_unstable_timer_counter_workaround())		\
		_val = timer_unstable_counter_workaround->read_##reg();\
	else						\
		_val = read_sysreg(reg);		\
	_val;						\
})

/*
 * These register accessors are marked inline so the compiler can
 * nicely work out which register we want, and chuck away the rest of
 * the code.
 */
static __always_inline
void arch_timer_reg_write_cp15(int access, enum arch_timer_reg reg, u32 val)
{
	if (access == ARCH_TIMER_PHYS_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			write_sysreg(val, cntp_ctl_el0);
			break;
		case ARCH_TIMER_REG_TVAL:
			write_sysreg(val, cntp_tval_el0);
			break;
		}
	} else if (access == ARCH_TIMER_VIRT_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			write_sysreg(val, cntv_ctl_el0);
			break;
		case ARCH_TIMER_REG_TVAL:
			write_sysreg(val, cntv_tval_el0);
			break;
		}
	}

	isb();
}

static __always_inline
u32 arch_timer_reg_read_cp15(int access, enum arch_timer_reg reg)
{
	if (access == ARCH_TIMER_PHYS_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			return read_sysreg(cntp_ctl_el0);
		case ARCH_TIMER_REG_TVAL:
			return arch_timer_reg_read_stable(cntp_tval_el0);
		}
	} else if (access == ARCH_TIMER_VIRT_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			return read_sysreg(cntv_ctl_el0);
		case ARCH_TIMER_REG_TVAL:
			return arch_timer_reg_read_stable(cntv_tval_el0);
		}
	}

	BUG();
}

static inline u32 arch_timer_get_cntfrq(void)
{
	return read_sysreg(cntfrq_el0);
}

static inline u32 arch_timer_get_cntkctl(void)
{
	return read_sysreg(cntkctl_el1);
}

static inline void arch_timer_set_cntkctl(u32 cntkctl)
{
	write_sysreg(cntkctl, cntkctl_el1);
}

static inline u64 arch_counter_get_cntpct(void)
{
	/*
	 * AArch64 kernel and user space mandate the use of CNTVCT.
	 */
	BUG();
	return 0;
}

#ifdef CONFIG_ARM64_ERRATUM_858921

static inline u64 arch_counter_get_cntvct(void)
{
	u64 cval;
	u64 cval2;

	isb();

	do {
		asm volatile("mrs %0, cntvct_el0" : "=r" (cval));
		asm volatile("mrs %0, cntvct_el0" : "=r" (cval2));
	} while(cval >> 32 != cval2 >> 32);

	return cval2;
}

#else

static inline u64 arch_counter_get_cntvct(void)
{
	isb();
	return arch_timer_reg_read_stable(cntvct_el0);
}

#endif

static inline int arch_timer_arch_init(void)
{
	return 0;
}

#endif
