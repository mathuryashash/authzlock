/* The Sandboxes guest kernel has no SysV IPC (shmget -> ENOSYS). Postgres needs only one tiny SysV segment
 * (an interlock) once shared_memory_type=mmap. Emulate it with a MAP_SHARED anonymous mapping, inherited by
 * forked backends. ponytail: single-segment fake, enough for one throwaway test cluster; not for production. */
#define _GNU_SOURCE
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>

static size_t seg_size = 4096;

int shmget(key_t key, size_t size, int flg) { (void)key; (void)flg; if (size) seg_size = size; return 4242; }
void *shmat(int id, const void *addr, int flg) {
    (void)id; (void)addr; (void)flg;
    void *p = mmap(NULL, seg_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? (void *)-1 : p;
}
int shmdt(const void *addr) { (void)addr; return 0; }
int shmctl(int id, int cmd, struct shmid_ds *buf) {
    (void)id;
    if (cmd == IPC_STAT && buf) { memset(buf, 0, sizeof *buf); buf->shm_segsz = seg_size; }
    return cmd == IPC_STAT || cmd == IPC_RMID || cmd == IPC_SET ? 0 : -1;
}
