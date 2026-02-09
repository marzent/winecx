/*
 * mach semaphore-based synchronization objects
 *
 * Copyright (C) 2018 Zebediah Figura
 * Copyright (C) 2023 Marc-Aurel Zent
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#ifdef __APPLE__

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_page_size.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/task.h>
#include <mach/semaphore.h>
#include <mach/mach_error.h>
#include <servers/bootstrap.h>
#include <os/lock.h>
#include <AvailabilityMacros.h>
#include <dlfcn.h>
#include <sched.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"
#include "wine/server.h"

#include "unix_private.h"
#include "msync.h"

WINE_DEFAULT_DEBUG_CHANNEL(sync);

static LONGLONG update_timeout( ULONGLONG end )
{
    LARGE_INTEGER now;
    LONGLONG timeleft;

    NtQuerySystemTime( &now );
    timeleft = end - now.QuadPart;
    if (timeleft < 0) timeleft = 0;
    return timeleft;
}

#define UL_COMPARE_AND_WAIT_SHARED  0x3
#define ULF_WAKE_ALL                0x00000100
#define ULF_NO_ERRNO                0x01000000
extern int __ulock_wake( uint32_t operation, void *addr, uint64_t wake_value );
extern int __ulock_wait( uint32_t operation, void *addr, uint64_t value, uint32_t timeout ); /* timeout is specified in microseconds */
#ifdef MAC_OS_VERSION_11_0
extern int __ulock_wait2( uint32_t operation, void *addr, uint64_t value, uint64_t timeout_ns, uint64_t value2 ) __attribute__((weak_import));
#endif

static inline int ulock_wait( uint32_t operation, void *addr, uint64_t value, uint64_t timeout_ns )
{
#ifdef MAC_OS_VERSION_11_0
    if (__builtin_available( macOS 11.0, * ))
    {
        return __ulock_wait2( operation, addr, value, timeout_ns, 0 );
    }
    else
#endif
    {
        uint32_t timeout_us = timeout_ns / 1000;
        /* Avoid a 0 timeout for small timeout_ns values */
        uint32_t adjust = (timeout_us == 0) & (timeout_ns != 0);
        return __ulock_wait( operation, addr, value, timeout_us + adjust );
    }
}

/*
 * Faster to directly do the syscall and inline everything, taken and slightly adapted
 * from xnu/libsyscall/mach/mach_msg.c
 */

#define LIBMACH_OPTIONS64 (MACH_SEND_INTERRUPT|MACH_RCV_INTERRUPT)
#define MACH64_SEND_MQ_CALL 0x0000000400000000ull

typedef mach_msg_return_t (*mach_msg2_trap_ptr_t)( void *data, uint64_t options,
    uint64_t msgh_bits_and_send_size, uint64_t msgh_remote_and_local_port,
    uint64_t msgh_voucher_and_id, uint64_t desc_count_and_rcv_name,
    uint64_t rcv_size_and_priority, uint64_t timeout );

static mach_msg2_trap_ptr_t mach_msg2_trap;

static inline mach_msg_return_t mach_msg2_internal( void *data, uint64_t option64, uint64_t msgh_bits_and_send_size,
    uint64_t msgh_remote_and_local_port, uint64_t msgh_voucher_and_id, uint64_t desc_count_and_rcv_name,
    uint64_t rcv_size_and_priority, uint64_t timeout)
{
    mach_msg_return_t mr;

    mr = mach_msg2_trap( data, option64 & ~LIBMACH_OPTIONS64, msgh_bits_and_send_size,
             msgh_remote_and_local_port, msgh_voucher_and_id, desc_count_and_rcv_name,
             rcv_size_and_priority, timeout );

    if (mr == MACH_MSG_SUCCESS)
        return MACH_MSG_SUCCESS;

    while (mr == MACH_SEND_INTERRUPTED)
        mr = mach_msg2_trap( data, option64 & ~LIBMACH_OPTIONS64, msgh_bits_and_send_size,
                 msgh_remote_and_local_port, msgh_voucher_and_id, desc_count_and_rcv_name,
                 rcv_size_and_priority, timeout );

    while (mr == MACH_RCV_INTERRUPTED)
        mr = mach_msg2_trap( data, option64 & ~LIBMACH_OPTIONS64, msgh_bits_and_send_size & 0xffffffffull,
                 msgh_remote_and_local_port, msgh_voucher_and_id, desc_count_and_rcv_name,
                 rcv_size_and_priority, timeout);

    return mr;
}

static inline mach_msg_return_t mach_msg2( mach_msg_header_t *data, uint64_t option64,
    mach_msg_size_t send_size, mach_msg_size_t rcv_size, mach_port_t rcv_name, uint64_t timeout,
    uint32_t priority)
{
    mach_msg_base_t *base;
    mach_msg_size_t descriptors;

    if (!mach_msg2_trap)
        return mach_msg( data, (mach_msg_option_t)option64, send_size,
                         rcv_size, rcv_name, timeout, priority );

    base = (mach_msg_base_t *)data;

    if ((option64 & MACH_SEND_MSG) &&
        (base->header.msgh_bits & MACH_MSGH_BITS_COMPLEX))
        descriptors = base->body.msgh_descriptor_count;
    else
        descriptors = 0;

#define MACH_MSG2_SHIFT_ARGS(lo, hi) ((uint64_t)hi << 32 | (uint32_t)lo)
    return mach_msg2_internal(data, option64 | MACH64_SEND_MQ_CALL,
               MACH_MSG2_SHIFT_ARGS(data->msgh_bits, send_size),
               MACH_MSG2_SHIFT_ARGS(data->msgh_remote_port, data->msgh_local_port),
               MACH_MSG2_SHIFT_ARGS(data->msgh_voucher_port, data->msgh_id),
               MACH_MSG2_SHIFT_ARGS(descriptors, rcv_name),
               MACH_MSG2_SHIFT_ARGS(rcv_size, priority), timeout);
#undef MACH_MSG2_SHIFT_ARGS
}

struct semaphore
{
    int count;
    int max;
    unsigned short msync_type;
    unsigned short refcount;
    int multiple_waiters;
};
C_ASSERT(sizeof(struct semaphore) == 16);

struct event
{
    int signaled;
    int unused;
    unsigned short msync_type;
    unsigned short refcount;
    int multiple_waiters;
};
C_ASSERT(sizeof(struct event) == 16);

struct mutex
{
    int tid;
    int count;  /* recursion count */
    unsigned short msync_type;
    unsigned short refcount;
    int multiple_waiters;
};
C_ASSERT(sizeof(struct mutex) == 16);

typedef struct
{
    mach_msg_header_t header;
    unsigned int shm_idx[MAXIMUM_WAIT_OBJECTS + 1];
} mach_register_message_t;

static mach_port_t server_port;

static int *shm_tid_map;

static const mach_msg_bits_t msgh_bits_send = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_COPY_SEND);

static inline mach_msg_return_t server_register_wait( unsigned int msgh_id, const int *objs,
                                void **objs_shm, int alert_obj, void *alert_obj_shm, int count )
{
    int i, is_mutex;
    mach_msg_return_t mr;
    __thread static mach_register_message_t message;

    message.header.msgh_remote_port = server_port;
    message.header.msgh_bits = msgh_bits_send;
    message.header.msgh_id = msgh_id;

    for (i = 0; i < count; i++)
    {
        struct event *obj = (struct event *)objs_shm[i];

        is_mutex = obj->msync_type == MSYNC_MUTEX ? 1 : 0;
        message.shm_idx[i] = objs[i]| (is_mutex << 28);
        __atomic_add_fetch( &obj->multiple_waiters, 1, __ATOMIC_SEQ_CST);
    }

    if (alert_obj)
    {
        struct event *obj = (struct event *)alert_obj_shm;

        message.shm_idx[count++] = alert_obj;
        __atomic_add_fetch( &obj->multiple_waiters, 1, __ATOMIC_SEQ_CST);
    }

    message.header.msgh_size = sizeof(mach_msg_header_t) +
                               count * sizeof(unsigned int);

    mr = mach_msg2( (mach_msg_header_t *)&message, MACH_SEND_MSG, message.header.msgh_size,
                     0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, 0 );

    if (mr != MACH_MSG_SUCCESS)
        ERR("Failed to send server register wait: %#x\n", mr);

    return mr;
}

static inline void server_remove_wait( unsigned int msgh_id, const int *objs, void **objs_shm,
                                       int alert_obj, void *alert_obj_shm, int count )
{
    int i;
    mach_msg_return_t mr;
    __thread static mach_register_message_t message;

    message.header.msgh_remote_port = server_port;
    message.header.msgh_bits = msgh_bits_send;
    message.header.msgh_id = msgh_id;

    for (i = 0; i < count; i++)
    {
        struct event *obj = (struct event *)objs_shm[i];

        int refs = __atomic_sub_fetch( &obj->multiple_waiters, 1, __ATOMIC_SEQ_CST);
        if (refs < 0)
            __atomic_store_n( &obj->multiple_waiters, 0, __ATOMIC_SEQ_CST);
        message.shm_idx[i] = objs[i];
    }

    if (alert_obj)
    {
        struct event *obj = (struct event *)alert_obj_shm;

        int refs = __atomic_sub_fetch( &obj->multiple_waiters, 1, __ATOMIC_SEQ_CST);
        if (refs < 0)
            __atomic_store_n( &obj->multiple_waiters, 0, __ATOMIC_SEQ_CST);
        message.shm_idx[count++] = alert_obj;
    }

    message.shm_idx[0] |= (1 << 29);

    message.header.msgh_size = sizeof(mach_msg_header_t) +
                               count * sizeof(unsigned int);

    mr = mach_msg2( (mach_msg_header_t *)&message, MACH_SEND_MSG, message.header.msgh_size,
                     0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, 0 );

    if (mr != MACH_MSG_SUCCESS)
        ERR("Failed to send server remove wait: %#x\n", mr);
}

static inline NTSTATUS msync_wait_single( int obj, void *obj_shm,
                                          ULONGLONG *end, int tid )
{
    int ret, val = 0;
    ULONGLONG ns_timeleft = 0;

    do 
    {
        if (((struct mutex *)obj_shm)->msync_type == MSYNC_MUTEX)
        {
            val = __atomic_load_n( (int *)obj_shm, __ATOMIC_ACQUIRE );
            if (!val || val == ~0)
                val = tid;
        }

        if (__atomic_load_n( (int *)obj_shm, __ATOMIC_ACQUIRE ) != val)
            return STATUS_PENDING;

        if (end)
        {
            ns_timeleft = update_timeout( *end ) * 100;
            if (!ns_timeleft) return STATUS_TIMEOUT;
        }
        ret = ulock_wait( UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO, obj_shm, val, ns_timeleft );
    } while (ret == -EINTR || ret == -EFAULT);

    if (ret == -ETIMEDOUT)
        return STATUS_TIMEOUT;

    return STATUS_SUCCESS;
}

static inline int check_shm_contention( void **objs_shm, void *alert_obj_shm, int count, int tid )
{
    int i, val;

    for (i = 0; i < count; i++)
    {
        val = __atomic_load_n((int *)objs_shm[i], __ATOMIC_SEQ_CST);
        if (((struct mutex *)objs_shm[i])->msync_type == MSYNC_MUTEX)
        {
            if (val == 0 || val == ~0 || val == tid) return 1;
        }
        else
        {
            if (val != 0)  return 1;
        }
    }

    if (alert_obj_shm)
    {
        val = __atomic_load_n((int *)alert_obj_shm, __ATOMIC_SEQ_CST);
        if (val != 0)  return 1;
    }

    return 0;
}

static NTSTATUS msync_wait_multiple( const int *objs, void **objs_shm, int alert_obj, void *alert_obj_shm,
                                     int count, ULONGLONG *end, int tid )
{
    int ret, val;
    int *addr = shm_tid_map + tid;
    ULONGLONG ns_timeleft = 0;
    mach_msg_return_t mr;
    unsigned int msgh_id;
    int total_count = count + (alert_obj ? 1 : 0);

    __atomic_store_n( addr, 2, __ATOMIC_RELEASE );
    msgh_id = (tid << 8) | total_count;
    mr = server_register_wait( msgh_id, objs, objs_shm, alert_obj, alert_obj_shm, count );

    if (mr != MACH_MSG_SUCCESS)
        return STATUS_PENDING;

    while (__atomic_load_n( addr, __ATOMIC_ACQUIRE ) == 2)
    {
        if (check_shm_contention( objs_shm, alert_obj_shm, count, tid ))
        {
            int i;
            for (i = 0; i < count; i++)
            {
                struct event *obj = (struct event *)objs_shm[i];

                int refs = __atomic_sub_fetch( &obj->multiple_waiters, 1, __ATOMIC_SEQ_CST);
                if (refs < 0)
                    __atomic_store_n( &obj->multiple_waiters, 0, __ATOMIC_SEQ_CST);
            }
            return STATUS_PENDING;
        }
    }

    do
    {
        if (end)
        {
            ns_timeleft = update_timeout( *end ) * 100;
            if (!ns_timeleft)
            {
                server_remove_wait( msgh_id, objs, objs_shm, alert_obj, alert_obj_shm, count );
                return STATUS_TIMEOUT;
            }
        }
        ret = ulock_wait( UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO, addr, 1, ns_timeleft );
        val = __atomic_load_n( addr, __ATOMIC_ACQUIRE );
        if (!val)
            break;
    } while (ret == -EINTR || ret == -EFAULT);

    server_remove_wait( msgh_id, objs, objs_shm, alert_obj, alert_obj_shm, count );

    if (ret == -ETIMEDOUT) return STATUS_TIMEOUT;

    return STATUS_SUCCESS;
}

int do_msync(void)
{
    static int do_msync_cached = -1;

    if (do_msync_cached == -1)
        do_msync_cached = getenv("WINEMSYNC") && atoi(getenv("WINEMSYNC"));

    return do_msync_cached;
}

static const mach_vm_size_t shm_tid_size = 64 * 1024 * 1024; /* 64 MB to index 24 bit tids */
static void **shm_addrs;
static int shm_addrs_size;  /* length of the allocated shm_addrs array */
static long pagesize;

typedef struct
{
    mach_msg_header_t header;
    int entry;
} mach_map_message_t;

typedef struct
{
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t descriptor;
    mach_msg_trailer_t trailer;
} mach_map_message_reply_t;

static void *request_shm_from_server( int entry, int tid )
{
    static __thread mach_map_message_t send_message;
    static __thread mach_map_message_reply_t receive_message;
    mach_msg_return_t mr;
    kern_return_t kr;
    mach_port_t reply_port;
    mach_vm_address_t map_address = 0;

    TRACE( "requesting shm entry %d from server\n", entry );

    kr = mach_port_allocate( mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port );

    if (kr != KERN_SUCCESS)
    {
        ERR( "Failed to allocate reply port: %s\n", mach_error_string( kr ) );
        return NULL;
    }

    kr = mach_port_insert_right( mach_task_self(), reply_port, reply_port, MACH_MSG_TYPE_MAKE_SEND );

    if (kr != KERN_SUCCESS)
    {
        ERR( "Failed to insert right into reply port: %s\n", mach_error_string( kr ) );
        mach_port_deallocate( mach_task_self(), reply_port );
        return NULL;
    }

    send_message.header.msgh_bits = MACH_MSGH_BITS_SET( MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND, 0, 0 );
    send_message.header.msgh_id = tid;
    send_message.header.msgh_size = sizeof(send_message);
    send_message.header.msgh_remote_port = server_port;
    send_message.header.msgh_local_port = reply_port;
    send_message.entry = entry;

    mr = mach_msg_overwrite( &send_message.header, MACH_SEND_MSG | MACH_RCV_MSG,
               send_message.header.msgh_size, sizeof(receive_message), reply_port,
               MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL, &receive_message.header, 0 );

    if (mr != MACH_MSG_SUCCESS)
    {
        ERR( "Failed to send/receive shm map request: %#x\n", mr );
    }
    else
    {
        mach_vm_size_t size = tid ? shm_tid_size : pagesize;

        TRACE( "mapping shm entry %u with size %llu\n", receive_message.descriptor.name, size );

        kr = mach_vm_map( mach_task_self(), &map_address, size, 0, VM_FLAGS_ANYWHERE,
                          receive_message.descriptor.name, 0, FALSE, VM_PROT_DEFAULT,
                          VM_PROT_DEFAULT, VM_INHERIT_NONE );

        if (kr != KERN_SUCCESS)
        {
            ERR( "Failed to map shm entry: %u: %d (%s)\n", receive_message.descriptor.name, kr, mach_error_string( kr ) );
            map_address = 0;
        }
    }

    mach_port_deallocate( mach_task_self(), reply_port );
    mach_port_deallocate( mach_task_self(), receive_message.descriptor.name );
    return (void *)map_address;
}

static os_unfair_lock shm_addrs_lock = OS_UNFAIR_LOCK_INIT;

static void *get_shm_slow( unsigned int idx )
{
    int entry  = (idx * 16) / pagesize;
    int offset = (idx * 16) % pagesize;
    void *ret;

    os_unfair_lock_lock( &shm_addrs_lock );

    if (entry >= shm_addrs_size)
    {
        int new_size = max(shm_addrs_size * 2, entry + 1);

        if (!(shm_addrs = realloc( shm_addrs, new_size * sizeof(shm_addrs[0]) )))
            ERR("Failed to grow shm_addrs array to size %d.\n", shm_addrs_size);
        memset( shm_addrs + shm_addrs_size, 0, (new_size - shm_addrs_size) * sizeof(shm_addrs[0]) );
        shm_addrs_size = new_size;
    }

    if (!shm_addrs[entry])
    {
        void *addr = request_shm_from_server( entry, 0 );
        if (!addr)
            ERR("Failed to map page %d (offset %#lx).\n", entry, entry * pagesize);

        TRACE("Mapping page %d at %p.\n", entry, addr);

        if (__sync_val_compare_and_swap( &shm_addrs[entry], 0, addr ))
            mach_vm_deallocate( mach_task_self(), (mach_vm_address_t)addr, pagesize ); /* someone beat us to it */
    }

    ret = (void *)((unsigned long)shm_addrs[entry] + offset);

    os_unfair_lock_unlock( &shm_addrs_lock );

    return ret;
}

static inline void *get_shm( const unsigned int idx )
{
    int entry = idx >> (vm_kernel_page_shift - 4);
    int offset = (idx << 4) & vm_kernel_page_mask;

    if (entry >= shm_addrs_size || !shm_addrs[entry])
        return get_shm_slow( idx );

    return (void *)((unsigned long)shm_addrs[entry] + offset);
}

void msync_close( int obj )
{
    static __thread mach_msg_header_t send_header;
    mach_msg_return_t mr;

    TRACE( "obj=%d.\n", obj );

    send_header.msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_COPY_SEND);
    send_header.msgh_id = obj | (1 << 28);
    send_header.msgh_size = sizeof(send_header);
    send_header.msgh_remote_port = server_port;

    mr = mach_msg2( &send_header, MACH_SEND_MSG, send_header.msgh_size,
                    0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, 0);

    if (mr != MACH_MSG_SUCCESS)
        ERR( "Failed to send message to server to close msync object %d: %#x\n", obj, mr );
}

void msync_init(void)
{
    struct stat st;
    mach_port_t bootstrap_port;
    void *dlhandle = dlopen( NULL, RTLD_NOW );
    char message_port_name[28];

    if (!do_msync())
    {
        /* make sure the server isn't running with WINEMSYNC */
        NTSTATUS ret;

        SERVER_START_REQ( get_inproc_alert_fd )
        {
            ret = wine_server_call( req );
        }
        SERVER_END_REQ;

        if (ret != STATUS_INVALID_PARAMETER)
        {
            ERR("Server is running with WINEMSYNC but this process is not, please enable WINEMSYNC or restart wineserver.\n");
            exit(1);
        }

        dlclose( dlhandle );
        return;
    }

    if (stat( config_dir, &st ) == -1)
        ERR("Cannot stat %s\n", config_dir);

    if (st.st_ino != (unsigned long)st.st_ino)
        snprintf( message_port_name, 28, "wine-%lx%08lx-msync", (unsigned long)((unsigned long long)st.st_ino >> 32), (unsigned long)st.st_ino );
    else
        snprintf( message_port_name, 28, "wine-%lx-msync", (unsigned long)st.st_ino );

    pagesize = (long)vm_kernel_page_size;

    shm_addrs = calloc( 128, sizeof(shm_addrs[0]) );
    shm_addrs_size = 128;

    /* Bootstrap mach wineserver communication */

    mach_msg2_trap = (mach_msg2_trap_ptr_t)dlsym( dlhandle, "mach_msg2_trap" );
    if (!mach_msg2_trap)
        WARN("Using mach_msg instead of mach_msg2\n");
    dlclose( dlhandle );

    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap_port) != KERN_SUCCESS)
    {
        ERR("Failed task_get_special_port\n");
        exit(1);
    }

    if (bootstrap_look_up(bootstrap_port, message_port_name, &server_port) != KERN_SUCCESS)
    {
        ERR("Failed bootstrap_look_up for %s\n", message_port_name);
        exit(1);
    }

    shm_tid_map = request_shm_from_server( 0, 1 );

    if (!shm_tid_map)
    {
        ERR("Failed to map tid shared memory");
        exit(1);
    }
}

static inline void signal_all( void *shm, unsigned int shm_idx )
{
    __thread static mach_msg_header_t send_header;
    struct event *event_obj = (struct event *)shm;

    __ulock_wake( UL_COMPARE_AND_WAIT_SHARED | ULF_WAKE_ALL, shm, 0 );

    if (!__atomic_load_n( &event_obj->multiple_waiters, __ATOMIC_SEQ_CST ))
        return;

    send_header.msgh_bits = msgh_bits_send;
    send_header.msgh_id = shm_idx;
    send_header.msgh_size = sizeof(send_header);
    send_header.msgh_remote_port = server_port;

    mach_msg2( &send_header, MACH_SEND_MSG, send_header.msgh_size, 0,
               MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, 0 );
}

NTSTATUS msync_release_semaphore_obj( int obj, ULONG count, ULONG *prev_count )
{
    struct semaphore *semaphore = get_shm( obj );
    ULONG current;

    do
    {
        current = semaphore->count;
        if (count + current > semaphore->max)
            return STATUS_SEMAPHORE_LIMIT_EXCEEDED;

    } while (__sync_val_compare_and_swap( &semaphore->count, current, count + current ) != current);

    if (prev_count) *prev_count = current;

    signal_all( (void *)semaphore, obj );
    return STATUS_SUCCESS;
}

NTSTATUS msync_query_semaphore_obj( int obj, SEMAPHORE_BASIC_INFORMATION *info )
{
    struct semaphore *semaphore = get_shm( obj );

    info->CurrentCount = semaphore->count;
    info->MaximumCount = semaphore->max;

    return STATUS_SUCCESS;
}

NTSTATUS msync_set_event_obj( int obj, LONG *prev_state )
{
    struct event *event = get_shm( obj );
    LONG current;

    if (!(current = __atomic_exchange_n( &event->signaled, 1, __ATOMIC_SEQ_CST )))
        signal_all( (void *)event, obj );

    if (prev_state) *prev_state = current;

    return STATUS_SUCCESS;
}

NTSTATUS msync_reset_event_obj( int obj, LONG *prev_state )
{
    struct event *event = get_shm( obj );
    LONG current;

    current = __atomic_exchange_n( &event->signaled, 0, __ATOMIC_SEQ_CST );

    if (prev_state) *prev_state = current;

    return STATUS_SUCCESS;
}

NTSTATUS msync_pulse_event_obj( int obj, LONG *prev_state )
{
    struct event *event = get_shm( obj );
    LONG current;

    /* This isn't really correct; an application could miss the write.
     * Unfortunately we can't really do much better. Fortunately this is rarely
     * used (and publicly deprecated). */
    if (!(current = __atomic_exchange_n( &event->signaled, 1, __ATOMIC_SEQ_CST )))
        signal_all( (void *)event, obj );

    /* Try to give other threads a chance to wake up. Hopefully erring on this
     * side is the better thing to do... */
    sched_yield();

    __atomic_store_n( &event->signaled, 0, __ATOMIC_SEQ_CST );

    if (prev_state) *prev_state = current;

    return STATUS_SUCCESS;
}

NTSTATUS msync_query_event_obj( int obj, EVENT_BASIC_INFORMATION *info )
{
    struct event *event = get_shm( obj );

    info->EventState = event->signaled;
    info->EventType = (event->msync_type == MSYNC_AUTO_EVENT ? SynchronizationEvent : NotificationEvent);

    return STATUS_SUCCESS;
}

NTSTATUS msync_release_mutex_obj( int obj, LONG *prev_count )
{
    struct mutex *mutex = get_shm( obj );

    if (mutex->tid != GetCurrentThreadId())
        return STATUS_MUTANT_NOT_OWNED;

    if (prev_count) *prev_count = mutex->count;

    if (!--mutex->count)
    {
        __atomic_store_n( &mutex->tid, 0, __ATOMIC_SEQ_CST );
        signal_all( (void *)mutex, obj );
    }

    return STATUS_SUCCESS;
}

NTSTATUS msync_query_mutex_obj( int obj, MUTANT_BASIC_INFORMATION *info )
{
    struct mutex *mutex = get_shm( obj );

    info->CurrentCount = 1 - mutex->count;
    info->OwnedByCaller = (mutex->tid == GetCurrentThreadId());
    info->AbandonedState = (mutex->tid == ~0);

    return STATUS_SUCCESS;
}

static NTSTATUS do_single_wait( int obj, void *obj_shm, int alert_obj, void *alert_obj_shm, ULONGLONG *end, int tid )
{
    NTSTATUS status;

    if (alert_obj)
    {
        if (__atomic_load_n( (int *)alert_obj_shm, __ATOMIC_SEQ_CST ))
            return STATUS_USER_APC;

        status = msync_wait_multiple( &obj, &obj_shm, alert_obj, alert_obj_shm, 1, end, tid );

        if (__atomic_load_n( (int *)alert_obj_shm, __ATOMIC_SEQ_CST ))
            return STATUS_USER_APC;
    }
    else
    {
        status = msync_wait_single( obj, obj_shm, end, tid );
    }
    return status;
}

NTSTATUS msync_wait_objs( const DWORD count, const int *objs, BOOLEAN wait_any,
                          int alert_obj, const LARGE_INTEGER *timeout )
{
    static const LARGE_INTEGER zero = {0};

    int current_tid = 0;
    static __thread void *objs_shm[MAXIMUM_WAIT_OBJECTS];
    int *alert_obj_shm = NULL;
    LARGE_INTEGER now;
    int single_wait = 0;
    ULONGLONG end;
    int i, ret;

    current_tid = GetCurrentThreadId();

    if (alert_obj)
    {
        alert_obj_shm = get_shm( alert_obj );
        if (!count) single_wait = 1;
    }
    else
    {
        if (count == 1) single_wait = 1;
    }

    NtQuerySystemTime( &now );
    if (timeout)
    {
        if (timeout->QuadPart == TIMEOUT_INFINITE)
            timeout = NULL;
        else if (timeout->QuadPart > 0)
            end = timeout->QuadPart;
        else
            end = now.QuadPart - timeout->QuadPart;
    }

    for (i = 0; i < count; i++)
        objs_shm[i] = (struct event *)get_shm( objs[i] );

    if (wait_any || count <= 1)
    {
        while (1)
        {
            /* Try to grab anything. */

            if (alert_obj)
            {
                /* We must check this first! The server may set an event that
                 * we're waiting on, but we need to return STATUS_USER_APC. */
                if (__atomic_load_n( alert_obj_shm, __ATOMIC_SEQ_CST ))
                    goto userapc;
            }

            for (i = 0; i < count; i++)
            {
                switch (((struct event *)objs_shm[i])->msync_type)
                {
                case MSYNC_SEMAPHORE:
                {
                    struct semaphore *semaphore = objs_shm[i];
                    int current, new;

                    new = __atomic_load_n( &semaphore->count, __ATOMIC_SEQ_CST );
                    while ((current = new))
                    {
                        if ((new = __sync_val_compare_and_swap( &semaphore->count, current, current - 1 )) == current)
                            return i;
                    }
                    break;
                }
                case MSYNC_MUTEX:
                {
                    struct mutex *mutex = objs_shm[i];
                    int tid;

                    if (mutex->tid == current_tid)
                    {
                        mutex->count++;
                        return i;
                    }

                    tid = 0;
                    if (__atomic_compare_exchange_n(&mutex->tid, &tid, current_tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                    {
                        mutex->count = 1;
                        return i;
                    }
                    else if (tid == ~0 && __atomic_compare_exchange_n(&mutex->tid, &tid, current_tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                    {
                        mutex->count = 1;
                        return STATUS_ABANDONED_WAIT_0 + i;
                    }

                    break;
                }
                case MSYNC_AUTO_EVENT:
                case MSYNC_AUTO_SERVER:
                {
                    struct event *event = objs_shm[i];
                    int signaled = 1;

                    if (__atomic_compare_exchange_n(&event->signaled, &signaled, 0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                        return i;

                    break;
                }
                case MSYNC_MANUAL_EVENT:
                case MSYNC_MANUAL_SERVER:
                {
                    struct event *event = objs_shm[i];

                    if (__atomic_load_n(&event->signaled, __ATOMIC_SEQ_CST))
                        return i;

                    break;
                }
                default:
                    ERR("Invalid type %#x for obj %d.\n", ((struct event *)objs_shm[i])->msync_type, objs[i]);
                    assert(0);
                }
            }

            /* Looks like everything is contended, so wait. */

            if (timeout && !timeout->QuadPart)
            {
                /* Unlike esync, we already know that we've timed out, so we
                 * can avoid a syscall. */
                return STATUS_TIMEOUT;
            }

            if (alert_obj && single_wait)
                ret = msync_wait_single( alert_obj, alert_obj_shm, timeout ? &end : NULL, current_tid );
            else if (single_wait)
                ret = msync_wait_single( objs[0], objs_shm[0], timeout ? &end : NULL, current_tid );
            else
                ret = msync_wait_multiple( objs, objs_shm, alert_obj, alert_obj_shm, count, timeout ? &end : NULL, current_tid );

            if (ret == STATUS_TIMEOUT) return STATUS_TIMEOUT;
        } /* while (1) */
    }
    else
    {
        /* Wait-all is a little trickier to implement correctly. Fortunately,
         * it's not as common.
         *
         * The idea is basically just to wait in sequence on every object in the
         * set. Then when we're done, try to grab them all in a tight loop. If
         * that fails, release any resources we've grabbed (and yes, we can
         * reliably do this—it's just mutexes and semaphores that we have to
         * put back, and in both cases we just put back 1), and if any of that
         * fails we start over.
         *
         * What makes this inherently bad is that we might temporarily grab a
         * resource incorrectly. Hopefully it'll be quick (and hey, it won't
         * block on wineserver) so nobody will notice. Besides, consider: if
         * object A becomes signaled but someone grabs it before we can grab it
         * and everything else, then they could just as well have grabbed it
         * before it became signaled. Similarly if object A was signaled and we
         * were blocking on object B, then B becomes available and someone grabs
         * A before we can, then they might have grabbed A before B became
         * signaled. In either case anyone who tries to wait on A or B will be
         * waiting for an instant while we put things back. */

        NTSTATUS status = STATUS_SUCCESS;

        while (1)
        {
            BOOL abandoned;

tryagain:
            abandoned = FALSE;

            /* First step: try to wait on each object in sequence. */

            for (i = 0; i < count; i++)
            {
                if (((struct mutex *)objs_shm[i])->msync_type == MSYNC_MUTEX)
                {
                    struct mutex *mutex = (struct mutex *)objs_shm[i];

                    if (mutex->tid == current_tid)
                        continue;

                    while (__atomic_load_n( &mutex->tid, __ATOMIC_SEQ_CST ))
                    {
                        status = do_single_wait( objs[i], objs_shm[i], alert_obj, alert_obj_shm, timeout ? &end : NULL, current_tid );
                        if (status != STATUS_PENDING)
                            break;
                    }
                }
                else
                {
                    /* this works for semaphores too */
                    struct event *event = (struct event *)objs_shm[i];

                    while (!__atomic_load_n( &event->signaled, __ATOMIC_SEQ_CST ))
                    {
                        status = do_single_wait( objs[i], objs_shm[i], alert_obj, alert_obj_shm, timeout ? &end : NULL, current_tid );
                        if (status != STATUS_PENDING)
                            break;
                    }
                }

                if (status == STATUS_TIMEOUT) return STATUS_TIMEOUT;
                if (status == STATUS_USER_APC) goto userapc;
            }

            /* If we got here and we haven't timed out, that means all of the
             * handles were signaled. Check to make sure they still are. */
            for (i = 0; i < count; i++)
            {

                if (((struct mutex *)objs_shm[i])->msync_type == MSYNC_MUTEX)
                {
                    struct mutex *mutex = (struct mutex *)objs_shm[i];
                    int tid = __atomic_load_n( &mutex->tid, __ATOMIC_SEQ_CST );

                    if (tid && tid != ~0 && tid != current_tid)
                        goto tryagain;
                }
                else
                {
                    struct event *event = (struct event *)objs_shm[i];

                    if (!__atomic_load_n( &event->signaled, __ATOMIC_SEQ_CST ))
                        goto tryagain;
                }
            }

            /* Yep, still signaled. Now quick, grab everything. */
            for (i = 0; i < count; i++)
            {
                switch (((struct event *)objs_shm[i])->msync_type)
                {
                case MSYNC_MUTEX:
                {
                    struct mutex *mutex = (struct mutex *)objs_shm[i];
                    int tid = __atomic_load_n( &mutex->tid, __ATOMIC_SEQ_CST );
                    if (tid == current_tid)
                        break;
                    if (tid && tid != ~0)
                        goto tooslow;
                    if (__sync_val_compare_and_swap( &mutex->tid, tid, current_tid ) != tid)
                        goto tooslow;
                    if (tid == ~0)
                        abandoned = TRUE;
                    break;
                }
                case MSYNC_SEMAPHORE:
                {
                    struct semaphore *semaphore = (struct semaphore *)objs_shm[i];
                    int current, new;

                    new = __atomic_load_n( &semaphore->count, __ATOMIC_SEQ_CST );
                    while ((current = new))
                    {
                        if ((new = __sync_val_compare_and_swap( &semaphore->count, current, current - 1 )) == current)
                            break;
                    }
                    if (!current)
                        goto tooslow;
                    break;
                }
                case MSYNC_AUTO_EVENT:
                case MSYNC_AUTO_SERVER:
                {
                    struct event *event = (struct event *)objs_shm[i];
                    if (!__sync_val_compare_and_swap( &event->signaled, 1, 0 ))
                        goto tooslow;
                    break;
                }
                default:
                    /* If a manual-reset event changed between there and
                     * here, it's shouldn't be a problem. */
                    break;
                }
            }

            /* If we got here, we successfully waited on every object.
             * Make sure to let ourselves know that we grabbed the mutexes. */
            for (i = 0; i < count; i++)
            {
                if (((struct mutex *)objs_shm[i])->msync_type == MSYNC_MUTEX)
                {
                    struct mutex *mutex = (struct mutex *)objs_shm[i];
                    mutex->count++;
                }
            }

            if (abandoned) return STATUS_ABANDONED;

            return STATUS_SUCCESS;

tooslow:
            for (--i; i >= 0; i--)
            {
                switch (((struct event *)objs_shm[i])->msync_type)
                {
                case MSYNC_MUTEX:
                {
                    struct mutex *mutex = (struct mutex *)objs_shm[i];
                    /* HACK: This won't do the right thing with abandoned
                     * mutexes, but fixing it is probably more trouble than
                     * it's worth. */
                    __atomic_store_n( &mutex->tid, 0, __ATOMIC_SEQ_CST );
                    break;
                }
                case MSYNC_SEMAPHORE:
                {
                    struct semaphore *semaphore = (struct semaphore *)objs_shm[i];
                    __sync_fetch_and_add( &semaphore->count, 1 );
                    break;
                }
                case MSYNC_AUTO_EVENT:
                case MSYNC_AUTO_SERVER:
                {
                    struct event *event = (struct event *)objs_shm[i];
                    __atomic_store_n( &event->signaled, 1, __ATOMIC_SEQ_CST );
                    break;
                }
                default:
                    /* doesn't need to be put back */
                    break;
                }
            }
        } /* while (1) */
    } /* else (wait-all) */

    assert(0);  /* shouldn't reach here... */

userapc:
    /* We have to make a server call anyway to get the APC to execute, so just
     * delegate down to server_wait(). */
    ret = server_wait( NULL, 0, SELECT_INTERRUPTIBLE | SELECT_ALERTABLE, &zero );

    /* This can happen if we received a system APC, and the APC fd was woken up
     * before we got SIGUSR1. poll() doesn't return EINTR in that case. The
     * right thing to do seems to be to return STATUS_USER_APC anyway. */
    if (ret == STATUS_TIMEOUT) ret = STATUS_USER_APC;
    return ret;
}

#else /* __APPLE__ */

int do_msync(void)
{
    return 0;
}

void msync_init(void)
{
}

void msync_close( int obj )
{
}

#endif /* __APPLE__ */
