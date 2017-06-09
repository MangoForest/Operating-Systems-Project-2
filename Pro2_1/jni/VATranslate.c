#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdint.h>

#define VA_MAX (4 * 1024 * 1024 * 1024)
#define PAGE_SHIFT 12
#define TASK_SIZE (0xC0000000 - 0x01000000)
#define PGDIR_SHIFT 21
#define PGDIR_SIZE (1<<PGDIR_SHIFT)
#define NR_PGD_ENTRY (TASK_SIZE / PGDIR_SIZE)
#define NR_PTE_ENTRY (4096 / 8)
#define PGD_SIZE (NR_PGD_ENTRY * 4)
#define PTE_SIZE (NR_PGD_ENTRY * 4096)

#define PTRS_PER_PTE 512


int main(int argc, const char *argv[])
{
	if (argc!=3)
	{
		printf("Usage: ./VATranslate pid #VM\n");
		exit(128);
	}
	pid_t pid = atoi(argv[1]);
	unsigned long vaddr = strtoll(argv[2], NULL, 16);
	void *fake_pgd_base, *page_table_addr;
	fake_pgd_base = mmap(NULL, PGD_SIZE, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (fake_pgd_base == MAP_FAILED) {
		perror("[fatal] mmap");
		return 1;
	}

	page_table_addr = mmap(NULL, PTE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (page_table_addr == MAP_FAILED) {
		perror("[fatal] mmap2");
		return 1;
	}
	
	if(syscall(378, pid, (unsigned long)fake_pgd_base, (unsigned long) page_table_addr, 0x00000000,0xFFFFFFFF)<0)
	{
		perror("[fatal] sysctem call");
		return -errno;
	}
	
	unsigned long *f_pgd_base = (unsigned long *) fake_pgd_base;
	int pgd_index = vaddr>>21;
	unsigned long *pte_base = (unsigned long *) f_pgd_base[pgd_index];
	int pte_index = ((vaddr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
	unsigned long va = (pgd_index<<21)+(pte_index<<12);
	unsigned long offset = (vaddr<<20)>>20;
	printf("Virtual address:0x%lx\t", vaddr);
	printf("Physical address:0x%08lx\t\n", ((pte_base[pte_index] >> 12) << 12)+offset);
	
	return 0;
}
