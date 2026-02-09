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

#ifdef __APPLE__

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/mman.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_page_size.h>
#include <mach/vm_map.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/task.h>
#include <mach/semaphore.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <servers/bootstrap.h>
#include <sched.h>
#include <dlfcn.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "handle.h"
#include "request.h"
#include "msync.h"

#define UL_COMPARE_AND_WAIT_SHARED  0x3
#define ULF_WAKE_ALL                0x00000100
extern int __ulock_wake( uint32_t operation, void *addr, uint64_t wake_value );


#define MACH_CHECK_ERROR(ret, operation) \
    if (ret != KERN_SUCCESS) \
        fprintf(stderr, "msync: error: %s failed with %d: %s\n", \
            operation, ret, mach_error_string(ret));

/* Private API to register a mach port with the bootstrap server */
extern kern_return_t bootstrap_register2( mach_port_t bp, name_t service_name, mach_port_t sp, int flags );

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

static mach_port_name_t receive_port;

struct tid_node
{
    struct tid_node *next;
    int tid;
};

#define MAX_POOL_NODES 0x80000

struct node_memory_pool
{
    struct tid_node *nodes;
    struct tid_node **free_nodes;
    unsigned int count;
};

static struct node_memory_pool *pool;

static void pool_init(void)
{
    unsigned int i;
    pool = malloc( sizeof(struct node_memory_pool) );
    pool->nodes = malloc( MAX_POOL_NODES * sizeof(struct tid_node) );
    pool->free_nodes = malloc( MAX_POOL_NODES * sizeof(struct tid_node *) );
    pool->count = MAX_POOL_NODES;

    for (i = 0; i < MAX_POOL_NODES; i++)
        pool->free_nodes[i] = &pool->nodes[i];
}

static inline struct tid_node *pool_alloc(void)
{
    if (pool->count == 0)
    {
        fprintf( stderr, "msync: warn: node memory pool exhausted\n" );
        return malloc( sizeof(struct tid_node) );
    }
    return pool->free_nodes[--pool->count];
}

static inline void pool_free( struct tid_node *node )
{
    if (node < pool->nodes || node >= pool->nodes + MAX_POOL_NODES)
    {
        free(node);
        return;
    }
    pool->free_nodes[pool->count++] = node;
}

struct tid_list
{
    struct tid_node *head;
};

static struct tid_list *tid_map;
static size_t tid_map_size;
static int *shm_tid_map;
static const mach_vm_size_t shm_tid_size = 64 * 1024 * 1024; /* 64 MB to index 24 bit tids */

/* This function should only be called from get_tid_list() */
static void grow_tid_map( unsigned int shm_idx )
{
    size_t new_size = max(tid_map_size ? tid_map_size * 2 : 256, shm_idx + 1);
    struct tid_list *new_tid_map;

    new_tid_map = realloc( tid_map, new_size * sizeof(struct tid_list) );
    assert( new_tid_map );
    memset( new_tid_map + tid_map_size, 0, (new_size - tid_map_size) * sizeof(struct tid_list) );
    tid_map = new_tid_map;
    tid_map_size = new_size;
}

/* This function is not thread-safe and should only be called from the message thread! */
static inline struct tid_list *get_tid_list( unsigned int shm_idx )
{
    if( shm_idx >= tid_map_size ) grow_tid_map( shm_idx );
    return tid_map + shm_idx;
}

static inline void add_tid( unsigned int shm_idx, int tid )
{
    struct tid_node *new_node;
    struct tid_list *list = get_tid_list( shm_idx );

    new_node = pool_alloc();
    new_node->tid = tid;

    new_node->next = list->head;
    list->head = new_node;
}

static inline void remove_tid( unsigned int shm_idx, int tid )
{
    struct tid_node *current, *prev = NULL;
    struct tid_list *list = get_tid_list( shm_idx );

    current = list->head;
    while (current != NULL)
    {
        if (current->tid == tid)
        {
            if (prev == NULL)
                list->head = current->next;
            else
                prev->next = current->next;
            pool_free(current);
            break;
        }
        prev = current;
        current = current->next;
    }
}

static long pagesize;
static void *get_shm( unsigned int idx );

typedef struct
{
    mach_msg_header_t header;
    unsigned int shm_idx[MAXIMUM_WAIT_OBJECTS + 1];
    mach_msg_trailer_t trailer;
} mach_register_message_t;

typedef struct
{
    mach_msg_header_t header;
    int entry;
    mach_msg_trailer_t trailer;
} mach_map_message_t;

typedef struct
{
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t descriptor;
} mach_map_message_reply_t;

static void **shm_addrs;
static int shm_addrs_size;  /* length of the allocated shm_addrs array */

static void send_shm_to_client( mach_map_message_t *message )
{
    static mach_map_message_reply_t reply;
    mach_msg_return_t mr;
    kern_return_t kr;
    memory_object_offset_t offset = 0;
    mach_vm_size_t entry_size = 0;
    mach_port_t entry_port = MACH_PORT_NULL;

    if (message->header.msgh_id)
    {
        offset = (memory_object_offset_t)shm_tid_map;
        entry_size = shm_tid_size;
    }
    else if (message->entry < shm_addrs_size)
    {
        offset = (memory_object_offset_t)shm_addrs[message->entry];
        entry_size = pagesize;
    }
    else
        fprintf( stderr, "msync: error: client requested out-of-bounds shm entry %d\n", message->entry );

    kr = mach_make_memory_entry_64( mach_task_self(), &entry_size, offset, VM_PROT_DEFAULT,
                                    &entry_port, MACH_PORT_NULL );

    if (kr != KERN_SUCCESS)
        fprintf( stderr, "msync: error: mach_make_memory_entry_64 failed with %d: %s\n", kr, mach_error_string( kr ) );

    reply.header.msgh_bits = MACH_MSGH_BITS_SET( MACH_MSG_TYPE_COPY_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX );
    reply.header.msgh_id = message->header.msgh_id;
    reply.header.msgh_size = sizeof(reply);
    reply.header.msgh_remote_port = message->header.msgh_remote_port;
    reply.body.msgh_descriptor_count = 1;
    reply.descriptor.name = entry_port;
    reply.descriptor.disposition = MACH_MSG_TYPE_COPY_SEND;
    reply.descriptor.type = MACH_MSG_PORT_DESCRIPTOR;

    mr = mach_msg2( &reply.header, MACH_SEND_MSG, reply.header.msgh_size,
                    0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, 0 );

    if (mr != MACH_MSG_SUCCESS)
        fprintf( stderr, "msync: error: failed to send shm entry to client: %x\n", mr );

    mach_port_deallocate( mach_task_self(), message->header.msgh_remote_port );
    mach_port_deallocate( mach_task_self(), entry_port );
}

static inline void unregister_wait( mach_register_message_t *message, unsigned int tid, unsigned int count )
{
    int i;

    for (i = 0; i < count; i++)
        remove_tid( message->shm_idx[i], tid );
}

static inline void wake_tid( int tid )
{
    int *shm = shm_tid_map + tid;

    __atomic_store_n( shm, 0, __ATOMIC_RELEASE );
    __ulock_wake( UL_COMPARE_AND_WAIT_SHARED, (void *)shm, 0 );
}

static inline void signal_all_internal( unsigned int shm_idx )
{
    struct tid_node *current, *temp;
    struct tid_list *list = get_tid_list( shm_idx );

    current = list->head;
    list->head = NULL;

    while (current)
    {
        wake_tid( current->tid );
        temp = current;
        current = current->next;
        pool_free(temp);
    }
}

/* shm layout for msync objects. */
struct msync_shm
{
    int low;
    int high;
    unsigned short msync_type;
    unsigned short refcount;
    int multiple_waiters;
};

static unsigned int last_allocated_idx = 1;
static unsigned int last_destroyed_idx = UINT32_MAX;

static inline void destroy_all_internal( unsigned int shm_idx )
{
    struct msync_shm *obj = get_shm( shm_idx );
    unsigned short refcount = __atomic_load_n( &obj->refcount, __ATOMIC_SEQ_CST );

    if (!refcount)
    {
        fprintf( stderr, "msync: error: destroy_all on already destroyed shm idx %u with refcount %d\n", shm_idx, refcount );
        return;
    }

    refcount = __atomic_sub_fetch( &obj->refcount, 1, __ATOMIC_SEQ_CST );

    if (!refcount) last_destroyed_idx = shm_idx;
}

/*
 * thread-safe sequentially consistent guarantees relative to register/unregister
 * client-side are made by the mach messaging queue
 */
static inline mach_msg_return_t destroy_all( unsigned int shm_idx )
{
    static mach_msg_header_t send_header;
    send_header.msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_COPY_SEND);
    send_header.msgh_id = shm_idx | (1 << 28);
    send_header.msgh_size = sizeof(send_header);
    send_header.msgh_remote_port = receive_port;

    return mach_msg2( &send_header, MACH_SEND_MSG, send_header.msgh_size,
                0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, 0);
}

static inline mach_msg_return_t signal_all( unsigned int shm_idx, int *shm )
{
    static mach_msg_header_t send_header;
    struct msync_shm *obj = (struct msync_shm *)shm;

    __ulock_wake( UL_COMPARE_AND_WAIT_SHARED | ULF_WAKE_ALL, (void *)shm, 0 );
    if (!__atomic_load_n( &obj->multiple_waiters, __ATOMIC_SEQ_CST ))
        return MACH_MSG_SUCCESS;

    send_header.msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_COPY_SEND);
    send_header.msgh_id = shm_idx;
    send_header.msgh_size = sizeof(send_header);
    send_header.msgh_remote_port = receive_port;

    return mach_msg2( &send_header, MACH_SEND_MSG, send_header.msgh_size,
                0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, 0 );
}

static inline mach_msg_return_t receive_mach_msg( mach_register_message_t *buffer )
{
    return mach_msg2( (mach_msg_header_t *)buffer, MACH_RCV_MSG, 0,
            sizeof(*buffer), receive_port, MACH_MSG_TIMEOUT_NONE, 0 );
}

static inline void decode_msgh_id( unsigned int msgh_id, unsigned int *tid, unsigned int *count )
{
    *tid = msgh_id >> 8;
    *count = msgh_id & 0xFF;
}

static inline unsigned int check_bit( const unsigned int bit, unsigned int *shm_idx )
{
    unsigned int bit_val = (*shm_idx >> bit) & 1;
    *shm_idx &= ~(1u << bit);
    return bit_val;
}

static void *mach_message_pump( void *args )
{
    int i, val;
    unsigned int tid, count, is_mutex;
    struct msync_shm *obj;
    mach_msg_return_t mr;
    mach_register_message_t receive_message = { 0 };
    sigset_t set;

    sigfillset( &set );
    pthread_sigmask( SIG_BLOCK, &set, NULL );

    for (;;)
    {
        mr = receive_mach_msg( &receive_message );
        if (mr != MACH_MSG_SUCCESS)
        {
            fprintf( stderr, "msync: failed to receive message\n");
            continue;
        }

        /*
         * A complex mach message, where the client expects a reply,
         * is a send back a mach memory entry request.
         */
        if (receive_message.header.msgh_remote_port != MACH_PORT_NULL)
        {
            send_shm_to_client( (mach_map_message_t *)&receive_message );
            continue;
        }

        /*
         * A message with no body is a signal_all or destroy_all operation where the shm_idx
         * is the msgh_id and the type of operation is decided by the 29th bit.
         * (The shared memory index is only a 28-bit integer at max)
         * See signal_all( unsigned int shm_idx ) and destroy_all( unsigned int shm_idx )above.
         */
        if (receive_message.header.msgh_size == sizeof(mach_msg_header_t))
        {
            if (check_bit( 28, (unsigned int *)&receive_message.header.msgh_id ))
                destroy_all_internal( receive_message.header.msgh_id );
            else
                signal_all_internal( receive_message.header.msgh_id );
            continue;
        }

        /*
         * Finally server_register_wait and server_unregister_wait
         */
        decode_msgh_id( receive_message.header.msgh_id, &tid, &count );
        for (i = 0; i < count; i++)
        {
            if (i == 0 && check_bit( 29, receive_message.shm_idx + i ))
            {
                unregister_wait( &receive_message, tid, count );
                break;
            }
            is_mutex = check_bit( 28, receive_message.shm_idx + i );
            obj = get_shm( receive_message.shm_idx[i] );
            val = __atomic_load_n( &obj->low, __ATOMIC_SEQ_CST );
            if ((is_mutex && (val == 0 || val == ~0 || val == tid)) || (!is_mutex && val != 0))
            {
                if (i > 1) unregister_wait( &receive_message, tid, i );
                wake_tid( tid );
                break;
            }
            add_tid( receive_message.shm_idx[i], tid );
            if (i == count - 1)
            {
                /* The client can stop spinning and safely start waiting now */
                __atomic_store_n( shm_tid_map + tid, 1, __ATOMIC_RELEASE );
            }
        }
    }

    return NULL;
}

int do_msync(void)
{
    static int do_msync_cached = -1;

    if (do_msync_cached == -1)
    {
        do_msync_cached = getenv("WINEMSYNC") && atoi(getenv("WINEMSYNC"));
    }

    return do_msync_cached;
}

static void set_thread_policy_qos( mach_port_t mach_thread_id )
{
    thread_extended_policy_data_t extended_policy;
    thread_precedence_policy_data_t precedence_policy;
    int throughput_qos, latency_qos;
    kern_return_t kr;

    latency_qos = LATENCY_QOS_TIER_0;
    kr = thread_policy_set( mach_thread_id, THREAD_LATENCY_QOS_POLICY,
                            (thread_policy_t)&latency_qos,
                            THREAD_LATENCY_QOS_POLICY_COUNT);
    if (kr != KERN_SUCCESS)
        fprintf( stderr, "msync: error setting thread latency QoS.\n" );

    throughput_qos = THROUGHPUT_QOS_TIER_0;
    kr = thread_policy_set( mach_thread_id, THREAD_THROUGHPUT_QOS_POLICY,
                            (thread_policy_t)&throughput_qos,
                            THREAD_THROUGHPUT_QOS_POLICY_COUNT);
    if (kr != KERN_SUCCESS)
        fprintf( stderr, "msync: error setting thread throughput QoS.\n" );

    extended_policy.timeshare = 0;
    kr = thread_policy_set( mach_thread_id, THREAD_EXTENDED_POLICY,
                            (thread_policy_t)&extended_policy,
                            THREAD_EXTENDED_POLICY_COUNT );
    if (kr != KERN_SUCCESS)
        fprintf( stderr, "msync: error setting extended policy\n" );

    precedence_policy.importance = 63;
    kr = thread_policy_set( mach_thread_id, THREAD_PRECEDENCE_POLICY,
                            (thread_policy_t)&precedence_policy,
                            THREAD_PRECEDENCE_POLICY_COUNT );
    if (kr != KERN_SUCCESS)
        fprintf( stderr, "msync: error setting precedence policy\n" );
}

void msync_init_shm(void)
{
    kern_return_t kr;

    if (!do_msync()) return;

    pagesize = (long)vm_kernel_page_size;

    shm_addrs = calloc( 128, sizeof(shm_addrs[0]) );
    shm_addrs_size = 128;

    kr = mach_vm_map( mach_task_self(), (mach_vm_address_t *)&shm_tid_map, shm_tid_size, 0, VM_FLAGS_ANYWHERE,
                      MACH_PORT_NULL, 0, FALSE, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_SHARE );

    if (kr != KERN_SUCCESS)
    {
        fprintf( stderr, "msync: error: mach_vm_map failed with %d: %s\n", kr, mach_error_string( kr ) );
        fatal_error( "could not map tid shared memory\n" );
    }
}

void msync_init(void)
{
    struct stat st;
    mach_port_t bootstrap_port;
    mach_port_limits_t limits;
    void *dlhandle = dlopen( NULL, RTLD_NOW );
    pthread_t message_thread;
    char message_port_name[28];

    if (!do_msync()) return;

    if (fstat( config_dir_fd, &st ) == -1)
        fatal_error( "cannot stat config dir\n" );

    if (st.st_ino != (unsigned long)st.st_ino)
        snprintf( message_port_name, 28, "wine-%lx%08lx-msync", (unsigned long)((unsigned long long)st.st_ino >> 32), (unsigned long)st.st_ino );
    else
        snprintf( message_port_name, 28, "wine-%lx-msync", (unsigned long)st.st_ino );

    /* Bootstrap mach server message pump */

    mach_msg2_trap = (mach_msg2_trap_ptr_t)dlsym( dlhandle, "mach_msg2_trap" );
    if (!mach_msg2_trap)
        fprintf( stderr, "msync: warning: using mach_msg instead of mach_msg2\n");
    dlclose( dlhandle );

    MACH_CHECK_ERROR(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &receive_port), "mach_port_allocate");

    MACH_CHECK_ERROR(mach_port_insert_right(mach_task_self(), receive_port, receive_port, MACH_MSG_TYPE_MAKE_SEND), "mach_port_insert_right");

    limits.mpl_qlimit = 50;

    if (getenv("WINEMSYNC_QLIMIT"))
        limits.mpl_qlimit = atoi(getenv("WINEMSYNC_QLIMIT"));

    MACH_CHECK_ERROR(mach_port_set_attributes( mach_task_self(), receive_port, MACH_PORT_LIMITS_INFO,
                                        (mach_port_info_t)&limits, MACH_PORT_LIMITS_INFO_COUNT), "mach_port_set_attributes");

    MACH_CHECK_ERROR(task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap_port), "task_get_special_port");

    MACH_CHECK_ERROR(bootstrap_register2(bootstrap_port, message_port_name, receive_port, 0), "bootstrap_register2");

    pool_init();

    if (pthread_create( &message_thread, NULL, mach_message_pump, NULL ))
    {
        perror("pthread_create");
        fatal_error( "could not create mach message pump thread\n" );
    }

    set_thread_policy_qos( pthread_mach_thread_np( message_thread )) ;

    fprintf( stderr, "msync: bootstrapped mach port on %s.\n", message_port_name );

    fprintf( stderr, "msync: up and running.\n" );
}

static struct list mutex_list = LIST_INIT(mutex_list);

void msync_destroy( struct msync *msync )
{
    struct msync_shm *shm = get_shm( msync->shm_idx );

    if (shm->msync_type == MSYNC_MUTEX)
        list_remove( &msync->mutex_entry );
    if (!msync->shm_idx) return;

    destroy_all( msync->shm_idx );
    free( msync );
}

static void *get_shm( unsigned int idx )
{
    int entry  = (idx * 16) / pagesize;
    int offset = (idx * 16) % pagesize;

    if (entry >= shm_addrs_size)
    {
        int new_size = max(shm_addrs_size * 2, entry + 1);

        if (!(shm_addrs = realloc( shm_addrs, new_size * sizeof(shm_addrs[0]) )))
            fprintf( stderr, "msync: couldn't expand shm_addrs array to size %d\n", entry + 1 );

        memset( shm_addrs + shm_addrs_size, 0, (new_size - shm_addrs_size) * sizeof(shm_addrs[0]) );

        shm_addrs_size = new_size;
    }

    if (!shm_addrs[entry])
    {
        kern_return_t kr;
        mach_vm_address_t address;

        kr = mach_vm_map( mach_task_self(), (mach_vm_address_t *)&address, (mach_vm_size_t)pagesize, 0, VM_FLAGS_ANYWHERE,
                          MACH_PORT_NULL, 0, FALSE, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_SHARE );
        MACH_CHECK_ERROR( kr, "mach_vm_map" );
        memset( (void *)address, 0, pagesize );

        if (debug_level)
            fprintf( stderr, "msync: Mapping page %d at %llu.\n", entry, address );

        if (__sync_val_compare_and_swap( &shm_addrs[entry], 0, (void *)address ))
            mach_vm_deallocate( mach_task_self(), address, pagesize ); /* someone beat us to it */
    }

    return (void *)((unsigned long)shm_addrs[entry] + offset);
}

static unsigned int msync_alloc_shm( int low, int high, enum msync_type type )
{
    unsigned int shm_idx;
    struct msync_shm *shm;

    shm_idx = min( last_destroyed_idx, last_allocated_idx + 1 );

    for(;;)
    {
        shm = get_shm( shm_idx );
        if (!__atomic_load_n( &shm->refcount, __ATOMIC_SEQ_CST ))
            break;

        shm_idx++;
    }

    last_allocated_idx = shm_idx;

    assert(shm);
    shm->low = low;
    shm->high = high;
    shm->msync_type = type;
    shm->multiple_waiters = 0;
    __atomic_store_n( &shm->refcount, 1, __ATOMIC_SEQ_CST );

    return shm_idx;
}

struct msync *create_msync( int low, int high, enum msync_type type )
{
    struct msync *msync = mem_alloc( sizeof(struct msync) );

    if (msync)
    {
        msync->shm_idx = msync_alloc_shm( low, high, type );
        if (type == MSYNC_MUTEX)
            list_add_tail( &mutex_list, &msync->mutex_entry );
    }

    return msync;
}

/* shm layout for events or event-like objects. */
struct msync_event
{
    int signaled;
    int unused;
    unsigned short msync_type;
    unsigned short refcount;
    int multiple_waiters;
};

void msync_set_event( struct msync *msync )
{
    struct msync_event *event = get_shm( msync->shm_idx );

    if (!__atomic_exchange_n( &event->signaled, 1, __ATOMIC_SEQ_CST ))
        signal_all( msync->shm_idx, (int *)event );
}

void msync_reset_event( struct msync *msync )
{
    struct msync_event *event = get_shm( msync->shm_idx );

    __atomic_store_n( &event->signaled, 0, __ATOMIC_SEQ_CST );
}

struct mutex
{
    int tid;
    int count;  /* recursion count */
    unsigned short msync_type;
    unsigned short refcount;
    int multiple_waiters;
};

void msync_abandon_mutexes( thread_id_t tid )
{
    struct msync *msync;

    LIST_FOR_EACH_ENTRY( msync, &mutex_list, struct msync, mutex_entry )
    {
        struct mutex *mutex = get_shm( msync->shm_idx );

        if (mutex->tid == tid)
        {
            if (debug_level)
                fprintf( stderr, "msync_abandon_mutexes() idx=%d\n", msync->shm_idx );
            mutex->tid = ~0;
            mutex->count = 0;
            signal_all ( msync->shm_idx, (int *)mutex );
        }
    }
}

void msync_grab_object( struct msync *msync )
{
    struct msync_shm *obj = get_shm( msync->shm_idx );

    __atomic_fetch_add( &obj->refcount, 1, __ATOMIC_SEQ_CST );
}

#else /* __APPLE__ */

int do_msync(void)
{
    return 0;
}

void msync_init_shm(void)
{
}

void msync_init(void)
{
}

#endif /* __APPLE__ */
