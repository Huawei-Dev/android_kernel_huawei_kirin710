/* hi3xxx_irq_affinity.h */

#ifndef HISI_IRQ_AFFINITY_H
#define HISI_IIRQ_AFFINITY_H

#include <linux/errno.h>
static inline int hisi_irqaffinity_register(unsigned int irq, int cpu) { return -ENOSYS; }
static inline void hisi_irqaffinity_unregister(unsigned int irq) { return; }
static inline void hisi_irqaffinity_status(void) { return; }
#endif /* HISI_IRQ_AFFINITY_H */
