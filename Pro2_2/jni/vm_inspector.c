#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>

/* 32-bit machine can address 4G */
#define VA_MAX (4 * 1024 * 1024 * 1024)

/* 4K standard; 12 bits to index into a 1-byte address */
#define PAGE_SIZE (4 * 1024)

/* Userspace memory size */
#define TASK_SIZE (0xC0000000 - 0x01000000)

#define PGDIR_SHIFT 21
#define PGDIR_SIZE (1 << PGDIR_SHIFT)

/* = 1528 */
#define NR_PGD_ENTRY (TASK_SIZE / PGDIR_SIZE)

#define NR_PTE_ENTRY (PAGE_SIZE / 8)
#define PGD_SIZE (NR_PGD_ENTRY * 4)
#define PTE_SIZE (NR_PGD_ENTRY * PAGE_SIZE)
#define PTRS_PER_PTE 512
#define PAGE_SHIFT 12
int expose(pid_t pid, void *fake_pgd, void *addr, unsigned long begin_vaddr, unsigned long end_vaddr)
{
	if (syscall(378, pid, (unsigned long) fake_pgd,
		    (unsigned long) addr,begin_vaddr,end_vaddr) < 0) {
		perror("[fatal] syscall");
		return -errno;
	}
	return 0;
}

int dump_pte(void *fake_pgd, int verbose,unsigned long begin_vaddr, unsigned long end_vaddr)
{
	int i, j;
	unsigned long *f_pgd_base = (unsigned long *) fake_pgd;
	int begin = begin_vaddr >> 21;
	int end = end_vaddr >> 21;
	for (i = begin; i < NR_PGD_ENTRY&&i<=end; i++) {
		int i_t = i - begin;
		unsigned long *pte_base = (unsigned long *) f_pgd_base[i_t];

		if (!pte_base)
			continue;
		int k = 0;
		if(i == begin) k = ((begin_vaddr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
		int e = NR_PTE_ENTRY-1;
		if(i == end) e= ((end_vaddr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
		for (j = k; j <= e; j++) {
			unsigned long va;

			if (!verbose && !pte_base[j])
				continue;
			va = (i << 21) + (j << 12);
			printf("0x%x\t", i);
			printf("0x%08lx\t", va);
			printf("0x%08lx\t", (pte_base[j] >> 12) << 12);
			printf("%lu\t", (pte_base[j] & (1 << 1)) >> 1);
			printf("%lu\t", (pte_base[j] & (1 << 2)) >> 2);
			printf("%lu\t", (pte_base[j] & (1 << 6)) >> 6);
			printf("%lu\t", (pte_base[j] & (1 << 7)) >> 7);
			printf("%lu\n", (pte_base[j] & (1 << 9)) >> 9);
		}
	}
	return 0;
}

void usage(const char *argv0)
{
	printf("Usage: %s [-v] pid begin_vaddr end_vaddr\n", argv0);
	exit(128);
}

int main(int argc, const char *argv[])
{
	pid_t pid = -1;
	int verbose = 0;
	void *fake_pgd, *addr;
	unsigned long begin_vaddr;
	unsigned long end_vaddr;


	if (argc != 4 && argc != 5)
		usage(argv[0]);
	if (!strcmp(argv[1], "-v")) {
		verbose = 1;
		if (argc < 4)
			usage(argv[0]);
		pid = atoi(argv[2]);
		begin_vaddr = strtoll(argv[3],NULL,16);
		end_vaddr = strtoll(argv[4],NULL,16);
	} else if (argc > 4) {
		if (!strcmp(argv[2], "-v"))
			verbose = 1;
		else
			usage(argv[0]);
		pid = atoi(argv[1]);
		begin_vaddr = strtoll(argv[2],NULL,16);
		end_vaddr = strtoll(argv[3],NULL,16);
	} else{
		pid = atoi(argv[1]);
		begin_vaddr = strtoll(argv[2],NULL,16);
		end_vaddr = strtoll(argv[3],NULL,16);
	}

	fake_pgd = mmap(NULL, PGD_SIZE, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (fake_pgd == MAP_FAILED) {
		perror("[fatal] mmap");
		return 1;
	}

	addr = mmap(NULL, PTE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (addr == MAP_FAILED) {
		perror("[fatal] mmap2");
		return 1;
	}

	if (expose(pid, fake_pgd, addr,begin_vaddr,end_vaddr) < 0)
		return 1;
	dump_pte(fake_pgd, verbose, begin_vaddr,end_vaddr);

	munmap(fake_pgd, PGD_SIZE);
	munmap(addr, PTE_SIZE);

	return 0;
}
