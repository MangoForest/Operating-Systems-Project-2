#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <linux/syscalls.h>
#include <linux/pid.h>
#include <linux/expose.h>



SYSCALL_DEFINE2(get_pagetable_layout, struct pagetable_layout_info __user *,
		pgtbl_info, int, size)
{
	struct pagetable_layout_info layout_info;
	if (size < sizeof(struct pagetable_layout_info))
		return -EINVAL;
	layout_info.pgdir_shift = PGDIR_SHIFT;
	layout_info.pmd_shift = PMD_SHIFT;
	layout_info.page_shift = PAGE_SHIFT;
	if (copy_to_user(pgtbl_info, &layout_info, size))
		return -EFAULT;

	return 0;

}

static int
remap_pgd_and_pte(struct mm_struct *mm, unsigned long fake_pgd,
		  unsigned long page_table_addr, unsigned long begin_vaddr, unsigned long end_vaddr)
{
	struct mm_struct *current_mm = get_task_mm(current);
	unsigned long addr0, addr_iter;
	unsigned long *fake_pgd_iter;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pmdval_t pte_base;
	struct page *ptepage;
	struct vm_area_struct *vma;
	int i;
	int begin = begin_vaddr >> 21;
	int end = end_vaddr >> 21;

	addr0 = 0;
	pgd = mm->pgd;
	addr_iter = page_table_addr;
	fake_pgd_iter = (unsigned long *) fake_pgd;
	for (i = begin; i < USER_PTRS_PER_PGD && i <= end ; i++, fake_pgd_iter++) {
		if (pgd_none(*(pgd+i)) || unlikely(pgd_bad(*(pgd+i))))
			goto no_page_table;
		pud = pud_offset(pgd + i, addr0);
		if (pud_none(*pud) || unlikely(pud_bad(*pud)))
			goto no_page_table;
		pmd = pmd_offset(pud, addr0);
		if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
			goto no_page_table;
		pte_base = pmd_val(*pmd);
		ptepage = pmd_page(*pmd);
		if (!addr_iter && fake_pgd_iter) {
			atomic_dec(&ptepage->_count);
			continue;
		}
		if (put_user(addr_iter, fake_pgd_iter)) {
			printk(KERN_DEBUG "put_user failed\n");
			return -EINVAL;
		}
		*fake_pgd_iter = addr_iter;
		printk(KERN_INFO "PTE: 0x%lx\n", (unsigned long) pte_base);

		/* Read the mm with a read semaphore */
		down_read(&current_mm->mmap_sem);
		vma = find_vma(current_mm, addr_iter);
		up_read(&current_mm->mmap_sem);

		/* Write to the mm with a write semaphore */
		down_write(&current_mm->mmap_sem);
		if (remap_pfn_range(vma,
				    addr_iter,
				    (unsigned long) pte_base >> PAGE_SHIFT,
				    PAGE_SIZE,
				    vma->vm_page_prot) < 0) {
			printk(KERN_DEBUG "Invalid mapping: %lx to %lx\n",
			       (unsigned long) pte_base, addr_iter);
			up_write(&current_mm->mmap_sem);
			return -EINVAL;
		}
		up_write(&current_mm->mmap_sem);
		atomic_inc(&ptepage->_count);
		addr_iter += PAGE_SIZE;
		continue;
no_page_table:
		*fake_pgd_iter = 0;
	}
	return 0;
}


SYSCALL_DEFINE5(expose_page_table, pid_t, pid, unsigned long, fake_pgd,
		unsigned long, page_table_addr,unsigned long, begin_vaddr, unsigned long ,end_vaddr)
{
	struct task_struct *ts;
	struct pid *pid_struct;
	struct mm_struct *target_mm;
	int ret = 0;
	if(begin_vaddr>=end_vaddr)
	{
		return -EINVAL;
	}
	

	if (pid != -1) {
		pid_struct = find_get_pid(pid);
		if (!pid_struct) {
			printk(KERN_INFO "pid_struct failed\n");
			return -EINVAL;
		}
		ts = get_pid_task(pid_struct, PIDTYPE_PID);
		if (!ts) {
			printk(KERN_INFO "get_pid_task failed\n");
			return -EINVAL;
		}
		printk(KERN_INFO "Comm: %s, pid: %d\n", ts->comm, ts->pid);
	} else if (pid == -1)
		ts = current;
	else
		return -EINVAL;
	

	target_mm = get_task_mm(ts);
	if (!target_mm) {
		/* Must mean we hit an anonymous process, aka kernel thread */
		printk(KERN_INFO "get_task_mm failed\n");
		return -EINVAL;
	}

	/*
	 * Read-lock the target process as long as it's not the
	 * current process, in which case we write-lock it inside
	 * remap_pgd_and_pte.
	 */
	if (pid != -1)
		down_read(&target_mm->mmap_sem);
	ret = remap_pgd_and_pte(target_mm, fake_pgd, page_table_addr,begin_vaddr,end_vaddr);
	if (pid != -1)
		up_read(&target_mm->mmap_sem);

	return ret;
}