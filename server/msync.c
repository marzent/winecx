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
#ifdef __APPLE__
# include <mach/mach_init.h>
# include <mach/mach_port.h>
# include <mach/message.h>
# include <mach/port.h>
# include <mach/task.h>
# include <mach/semaphore.h>
# include <mach/error.h>
# include <servers/bootstrap.h>
#endif
#include <sched.h>
#include <pthread.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "handle.h"
#include "request.h"
#include "msync.h"

/*
 * We can't go higher because the maximum default size of of shared memory on XNU
 * is 4MB and we are using 8 bytes per entry.
 */
#define MAX_INDEX 0x80000

#ifdef __APPLE__

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

extern mach_msg_return_t mach_msg2_trap( void *data, uint64_t options, uint64_t msgh_bits_and_send_size,
    uint64_t msgh_remote_and_local_port, uint64_t msgh_voucher_and_id, uint64_t desc_count_and_rcv_name,
    uint64_t rcv_size_and_priority, uint64_t timeout);

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

struct sem_node
{
    struct sem_node *next;
    semaphore_t sem;
    int tid;
};

#define MAX_POOL_NODES MAX_INDEX * 2

struct node_memory_pool
{
    struct sem_node *nodes;
    struct sem_node **free_nodes;
    unsigned int count;
};

static struct node_memory_pool *pool;

static void pool_init(void)
{
    unsigned int i;
    pool = malloc( sizeof(struct node_memory_pool) );
    pool->nodes = malloc( MAX_POOL_NODES * sizeof(struct sem_node) );
    pool->free_nodes = malloc( MAX_POOL_NODES * sizeof(struct sem_node *) );
    pool->count = MAX_POOL_NODES;

    for (i = 0; i < MAX_POOL_NODES; i++)
        pool->free_nodes[i] = &pool->nodes[i];
}

static inline struct sem_node *pool_alloc(void)
{
    if (pool->count == 0)
    {
        fprintf( stderr, "msync: warn: node memory pool exhausted\n" );
        return malloc( sizeof(struct sem_node) );
    }
    return pool->free_nodes[--pool->count];
}

static inline void pool_free( struct sem_node *node )
{
    if (node < pool->nodes || node >= pool->nodes + MAX_POOL_NODES)
    {
        free(node);
        return;
    }
    pool->free_nodes[pool->count++] = node;
}

struct sem_list
{
    struct sem_node *head;
    int is_used;
    volatile int lock;
};

static inline void small_pause(void)
{
#if defined(__i386__) || defined(__x86_64__)
    __asm__ __volatile__( "rep;nop" : : : "memory" );
#else
    __asm__ __volatile__( "" : : : "memory" );
#endif
}

static inline void spinlock_lock( volatile int *lock )
{
    while(__atomic_test_and_set(lock, __ATOMIC_ACQUIRE))
        while(__atomic_load_n(lock, __ATOMIC_RELAXED))
            small_pause();
}

static inline void spinlock_unlock( volatile int *lock )
{
    __atomic_clear(lock, __ATOMIC_RELEASE);
}

static inline void add_sem( struct sem_list *list, semaphore_t sem, int tid )
{
    struct sem_node *new_node;

    new_node = pool_alloc();
    new_node->sem = sem;
    new_node->tid = tid;

    spinlock_lock(&list->lock);
    new_node->next = list->head;
    list->head = new_node;
    spinlock_unlock(&list->lock);
}

static inline void remove_sem( struct sem_list *list, int tid )
{
    struct sem_node *current, *prev = NULL;

    spinlock_lock(&list->lock);
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
    spinlock_unlock(&list->lock);
}

static inline void destroy_all( struct sem_list *list )
{
    struct sem_node *temp, *current;

    spinlock_lock(&list->lock);
    current = list->head;
    list->head = NULL;
    list->is_used = 0;
    spinlock_unlock(&list->lock);

    while (current)
    {
        semaphore_destroy( mach_task_self(), current->sem );
        temp = current;
        current = current->next;
        pool_free(temp);
    }
}

static struct sem_list mach_semaphore_map[MAX_INDEX];

static void signal_all_internal( unsigned int shm_idx )
{
    struct sem_node *current, *temp;
    struct sem_list *list = mach_semaphore_map + shm_idx;

    spinlock_lock(&list->lock);
    current = list->head;
    list->head = NULL;
    spinlock_unlock(&list->lock);

    while (current)
    {
        semaphore_signal( current->sem );
        semaphore_destroy( mach_task_self(), current->sem );
        temp = current;
        current = current->next;
        pool_free(temp);
    }
}

/* thread-safe sequentially consistent guarantees relative to register/unregister
 * are made by the mach messaging queue */
static inline mach_msg_return_t signal_all( unsigned int shm_idx )
{
    __thread static mach_msg_header_t send_header;
    send_header.msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_COPY_SEND);
    send_header.msgh_id = shm_idx;
    send_header.msgh_size = sizeof(send_header);
    send_header.msgh_remote_port = receive_port;
    
    return mach_msg2( &send_header, MACH_SEND_MSG, send_header.msgh_size,
                0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, 0);
}

static inline void add_sem_to_map( unsigned int index, semaphore_t sem, int tid )
{
    add_sem( mach_semaphore_map + index, sem, tid );
}

static inline void remove_sem_from_map( unsigned int index, int tid )
{
    remove_sem( mach_semaphore_map + index, tid );
}

typedef struct
{
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t descriptor;
    unsigned int shm_idx[MAXIMUM_WAIT_OBJECTS + 1];
    mach_msg_trailer_t trailer;
} mach_register_message_t;

typedef struct
{
    mach_msg_header_t header;
    unsigned int shm_idx[MAXIMUM_WAIT_OBJECTS + 1];
    mach_msg_trailer_t trailer;
} mach_unregister_message_t;

static inline mach_msg_return_t receive_mach_msg( mach_register_message_t *buffer )
{
    return mach_msg2( (mach_msg_header_t *)buffer, MACH_RCV_MSG, 0,
            sizeof(*buffer), receive_port, MACH_MSG_TIMEOUT_NONE, 0 );
}

static void *get_shm( unsigned int idx );

static inline void decode_msgh_id( unsigned int msgh_id, unsigned int *tid, unsigned int *count )
{
    *tid = msgh_id >> 8;
    *count = msgh_id & 0xFF;
}

static inline unsigned int check_if_mutex(unsigned int *shm_idx)
{
    unsigned int is_mutex = (*shm_idx >> 19) & 1;
    *shm_idx &= ~(1 << 19);
    return is_mutex;
}

static void *mach_message_pump( void *args )
{
    int i, val;
    unsigned int tid, count, is_mutex;
    int *addr;
    mach_msg_return_t mr;
    semaphore_t sem;
    mach_register_message_t receive_message = { 0 };
    mach_unregister_message_t *mach_unregister_message;
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
         * A message with no body is a signal_all operation where the shm_idx is the msgh_id.
         * See signal_all( unsigned int shm_idx ) above.
         */
        if (receive_message.header.msgh_size == sizeof(mach_msg_header_t))
        {
            signal_all_internal( receive_message.header.msgh_id );
            continue;
        }

        /*
         * A message with a body which is not complex means this is a
         * server_remove_wait operation
         */
        decode_msgh_id( receive_message.header.msgh_id, &tid, &count );
        if (!MACH_MSGH_BITS_IS_COMPLEX(receive_message.header.msgh_bits))
        {
            mach_unregister_message = (mach_unregister_message_t *)&receive_message;
            for (i = 0; i < count; i++)
                remove_sem_from_map( mach_unregister_message->shm_idx[i], tid );
                

            continue;
        }

        /*
         * Finally server_register_wait
         */
        sem = receive_message.descriptor.name;
        for (i = 0; i < count; i++)
        {
            is_mutex = check_if_mutex( receive_message.shm_idx + i );
            addr = (int *)get_shm( receive_message.shm_idx[i] );
            val = __atomic_load_n( addr, __ATOMIC_SEQ_CST );
            if ((is_mutex && (val == 0 || val == ~0 || val == tid)) || (!is_mutex && val != 0))
            {
                /* The client had a TOCTTOU we need to fix */
                semaphore_signal( sem );
                semaphore_destroy( mach_task_self(), sem );
                continue;
            }
            add_sem_to_map( receive_message.shm_idx[i], sem, tid );
        }
    }

    return NULL;
}

#endif

int do_msync(void)
{
#ifdef __APPLE__
    static int do_msync_cached = -1;

    if (do_msync_cached == -1)
    {
        do_msync_cached = getenv("WINEMSYNC") && atoi(getenv("WINEMSYNC"));
    }

    return do_msync_cached;
#else
    return 0;
#endif
}

static char shm_name[29];
static int shm_fd;
static const off_t shm_size = MAX_INDEX * 8;
static void **shm_addrs;
static int shm_addrs_size;  /* length of the allocated shm_addrs array */
static long pagesize;
static pthread_t message_thread;

static int is_msync_initialized;

static void cleanup(void)
{
    close( shm_fd );
    if (shm_unlink( shm_name ) == -1)
        perror( "shm_unlink" );
}

void msync_init(void)
{
#ifdef __APPLE__
    struct stat st;
    mach_port_t bootstrap_port;
    pthread_attr_t attr;
    mach_port_limits_t limits;
    struct sched_param param;

    if (fstat( config_dir_fd, &st ) == -1)
        fatal_error( "cannot stat config dir\n" );

    if (st.st_ino != (unsigned long)st.st_ino)
        sprintf( shm_name, "/wine-%lx%08lx-msync", (unsigned long)((unsigned long long)st.st_ino >> 32), (unsigned long)st.st_ino );
    else
        sprintf( shm_name, "/wine-%lx-msync", (unsigned long)st.st_ino );

    if (!shm_unlink( shm_name ))
        fprintf( stderr, "msync: warning: a previous shm file %s was not properly removed\n", shm_name );

    shm_fd = shm_open( shm_name, O_RDWR | O_CREAT | O_EXCL, 0644 );
    if (shm_fd == -1)
        perror( "shm_open" );

    pagesize = sysconf( _SC_PAGESIZE );

    mach_semaphore_map[0].is_used = 1;
    shm_addrs = calloc( 128, sizeof(shm_addrs[0]) );
    shm_addrs_size = 128;

    if (ftruncate( shm_fd, shm_size ) == -1)
    {
        perror( "ftruncate" );
        fatal_error( "could not initialize shared memory\n" );
    }
    
    /* Bootstrap mach server message pump */
    
    MACH_CHECK_ERROR(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &receive_port), "mach_port_allocate");

    MACH_CHECK_ERROR(mach_port_insert_right(mach_task_self(), receive_port, receive_port, MACH_MSG_TYPE_MAKE_SEND), "mach_port_insert_right");

    limits.mpl_qlimit = 50;

    if (getenv("WINEMSYNC_QLIMIT"))
        limits.mpl_qlimit = atoi(getenv("WINEMSYNC_QLIMIT"));

    MACH_CHECK_ERROR(mach_port_set_attributes( mach_task_self(), receive_port, MACH_PORT_LIMITS_INFO,
                                        (mach_port_info_t)&limits, MACH_PORT_LIMITS_INFO_COUNT), "mach_port_set_attributes");

    MACH_CHECK_ERROR(task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap_port), "task_get_special_port");

    MACH_CHECK_ERROR(bootstrap_register2(bootstrap_port, shm_name + 1, receive_port, 0), "bootstrap_register2");
    
    pool_init();

    pthread_attr_init(&attr);
    pthread_attr_setschedpolicy(&attr, SCHED_FIFO);

    if (pthread_create( &message_thread, NULL, mach_message_pump, NULL ))
    {
        perror("pthread_create");
        fatal_error( "could not create mach message pump thread\n" );
    }

    fprintf( stderr, "msync: bootstrapped mach port on %s.\n", shm_name + 1 );

    is_msync_initialized = 1;

    fprintf( stderr, "msync: up and running.\n" );

    atexit( cleanup );
#endif
}

static struct list mutex_list = LIST_INIT(mutex_list);

struct msync
{
    struct object  obj;
    unsigned int   shm_idx;
    enum msync_type type;
    struct list     mutex_entry;
};

static void msync_dump( struct object *obj, int verbose );
static unsigned int msync_get_msync_idx( struct object *obj, enum msync_type *type );
static unsigned int msync_map_access( struct object *obj, unsigned int access );
static void msync_destroy( struct object *obj );

const struct object_ops msync_ops =
{
    sizeof(struct msync),      /* size */
    &no_type,                  /* type */
    msync_dump,                /* dump */
    no_add_queue,              /* add_queue */
    NULL,                      /* remove_queue */
    NULL,                      /* signaled */
    NULL,                      /* get_esync_fd */
    msync_get_msync_idx,       /* get_msync_idx */
    NULL,                      /* satisfied */
    no_signal,                 /* signal */
    no_get_fd,                 /* get_fd */
    msync_map_access,          /* map_access */
    default_get_sd,            /* get_sd */
    default_set_sd,            /* set_sd */
    no_get_full_name,          /* get_full_name */
    no_lookup_name,            /* lookup_name */
    directory_link_name,       /* link_name */
    default_unlink_name,       /* unlink_name */
    no_open_file,              /* open_file */
    no_kernel_obj_list,        /* get_kernel_obj_list */
    no_close_handle,           /* close_handle */
    msync_destroy              /* destroy */
};

static void msync_dump( struct object *obj, int verbose )
{
    struct msync *msync = (struct msync *)obj;
    assert( obj->ops == &msync_ops );
    fprintf( stderr, "msync idx=%d\n", msync->shm_idx );
}

static unsigned int msync_get_msync_idx( struct object *obj, enum msync_type *type)
{
    struct msync *msync = (struct msync *)obj;
    *type = msync->type;
    return msync->shm_idx;
}

static unsigned int msync_map_access( struct object *obj, unsigned int access )
{
    /* Sync objects have the same flags. */
    if (access & GENERIC_READ)    access |= STANDARD_RIGHTS_READ | EVENT_QUERY_STATE;
    if (access & GENERIC_WRITE)   access |= STANDARD_RIGHTS_WRITE | EVENT_MODIFY_STATE;
    if (access & GENERIC_EXECUTE) access |= STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE;
    if (access & GENERIC_ALL)     access |= STANDARD_RIGHTS_ALL | EVENT_QUERY_STATE | EVENT_MODIFY_STATE;
    return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

static void msync_destroy( struct object *obj )
{
    struct msync *msync = (struct msync *)obj;
    if (msync->type == MSYNC_MUTEX)
        list_remove( &msync->mutex_entry );
#ifdef __APPLE__
    msync_destroy_semaphore( msync->shm_idx );
#endif
}

static void *get_shm( unsigned int idx )
{
    int entry  = (idx * 8) / pagesize;
    int offset = (idx * 8) % pagesize;

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
        void *addr = mmap( NULL, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, entry * pagesize );
        if (addr == (void *)-1)
        {
            fprintf( stderr, "msync: failed to map page %d (offset %#lx): ", entry, entry * pagesize );
            perror( "mmap" );
        }

        if (debug_level)
            fprintf( stderr, "msync: Mapping page %d at %p.\n", entry, addr );

        if (__sync_val_compare_and_swap( &shm_addrs[entry], 0, addr ))
            munmap( addr, pagesize ); /* someone beat us to it */
    }

    return (void *)((unsigned long)shm_addrs[entry] + offset);
}

static unsigned int shm_idx_counter = 1;

unsigned int msync_alloc_shm( int low, int high )
{
#ifdef __APPLE__
    int shm_idx, tries = 0;
    int *shm;

    /* this is arguably a bit of a hack, but we need some way to prevent
     * allocating shm for the master socket */
    if (!is_msync_initialized)
        return 0;

    shm_idx = shm_idx_counter;

    while (mach_semaphore_map[shm_idx].is_used)
    {
        shm_idx = (shm_idx + 1) % MAX_INDEX;
        if (tries++ > MAX_INDEX)
        {
            /* The ftruncate call can only be succesfully done with a non-zero length
             * once per shared memory region with XNU. We need to terminate now.
             * Also we initialized with the default maximum size anyways... */
            fatal_error( "too many msync objects\n" );
        }
    }
    mach_semaphore_map[shm_idx].is_used = 1;
    assert(mach_semaphore_map[shm_idx].head == NULL);
    shm_idx_counter = (shm_idx + 1) % MAX_INDEX;

    shm = get_shm( shm_idx );
    assert(shm);
    shm[0] = low;
    shm[1] = high;

    return shm_idx;
#else
    return 0;
#endif
}

static int type_matches( enum msync_type type1, enum msync_type type2 )
{
    return (type1 == type2) ||
           ((type1 == MSYNC_AUTO_EVENT || type1 == MSYNC_MANUAL_EVENT) &&
            (type2 == MSYNC_AUTO_EVENT || type2 == MSYNC_MANUAL_EVENT));
}

struct msync *create_msync( struct object *root, const struct unicode_str *name,
    unsigned int attr, int low, int high, enum msync_type type,
    const struct security_descriptor *sd )
{
#ifdef __APPLE__
    struct msync *msync;

    if ((msync = create_named_object( root, &msync_ops, name, attr, sd )))
    {
        if (get_error() != STATUS_OBJECT_NAME_EXISTS)
        {
            /* initialize it if it didn't already exist */

            /* Initialize the shared memory portion. We want to do this on the
             * server side to avoid a potential though unlikely race whereby
             * the same object is opened and used between the time it's created
             * and the time its shared memory portion is initialized. */

            msync->shm_idx = msync_alloc_shm( low, high );
            msync->type = type;
            if (type == MSYNC_MUTEX)
                list_add_tail( &mutex_list, &msync->mutex_entry );
        }
        else
        {
            /* validate the type */
            if (!type_matches( type, msync->type ))
            {
                release_object( &msync->obj );
                set_error( STATUS_OBJECT_TYPE_MISMATCH );
                return NULL;
            }
        }
    }

    return msync;
#else
    set_error( STATUS_NOT_IMPLEMENTED );
    return NULL;
#endif
}

/* shm layout for events or event-like objects. */
struct msync_event
{
    int signaled;
    int unused;
};

void msync_signal_all( unsigned int shm_idx )
{
    struct msync_event *event;

    if (debug_level)
        fprintf( stderr, "msync_signal_all: index %u\n", shm_idx );

    if (!shm_idx)
        return;

    event = get_shm( shm_idx );
    if (!__atomic_exchange_n( &event->signaled, 1, __ATOMIC_SEQ_CST ))
        signal_all( shm_idx );
}

void msync_wake_up( struct object *obj )
{
    enum msync_type type;

    if (debug_level)
        fprintf( stderr, "msync_wake_up: object %p\n", obj );

    if (obj->ops->get_msync_idx)
        msync_signal_all( obj->ops->get_msync_idx( obj, &type ) );
}

void msync_destroy_semaphore( unsigned int shm_idx )
{
    if (!shm_idx) return;

    destroy_all( mach_semaphore_map + shm_idx );
}

void msync_clear_shm( unsigned int shm_idx )
{
    struct msync_event *event;

    if (debug_level)
        fprintf( stderr, "msync_clear_shm: index %u\n", shm_idx );

    if (!shm_idx)
        return;

    event = get_shm( shm_idx );
    __atomic_store_n( &event->signaled, 0, __ATOMIC_SEQ_CST );
}

void msync_clear( struct object *obj )
{
    enum msync_type type;

    if (debug_level)
        fprintf( stderr, "msync_clear: object %p\n", obj );

    if (obj->ops->get_msync_idx)
        msync_clear_shm( obj->ops->get_msync_idx( obj, &type ) );
}

void msync_set_event( struct msync *msync )
{
    struct msync_event *event = get_shm( msync->shm_idx );
    assert( msync->obj.ops == &msync_ops );

    if (!__atomic_exchange_n( &event->signaled, 1, __ATOMIC_SEQ_CST ))
        signal_all( msync->shm_idx );
}

void msync_reset_event( struct msync *msync )
{
    struct msync_event *event = get_shm( msync->shm_idx );
    assert( msync->obj.ops == &msync_ops );

    __atomic_store_n( &event->signaled, 0, __ATOMIC_SEQ_CST );
}

struct mutex
{
    int tid;
    int count;  /* recursion count */
};

void msync_abandon_mutexes( struct thread *thread )
{
    struct msync *msync;

    LIST_FOR_EACH_ENTRY( msync, &mutex_list, struct msync, mutex_entry )
    {
        struct mutex *mutex = get_shm( msync->shm_idx );

        if (mutex->tid == thread->id)
        {
            if (debug_level)
                fprintf( stderr, "msync_abandon_mutexes() idx=%d\n", msync->shm_idx );
            mutex->tid = ~0;
            mutex->count = 0;
            signal_all ( msync->shm_idx );
        }
    }
}

DECL_HANDLER(create_msync)
{
    struct msync *msync;
    struct unicode_str name;
    struct object *root;
    const struct security_descriptor *sd;
    const struct object_attributes *objattr = get_req_object_attributes( &sd, &name, &root );

    if (!do_msync())
    {
        set_error( STATUS_NOT_IMPLEMENTED );
        return;
    }

    if (!objattr) return;

    if ((msync = create_msync( root, &name, objattr->attributes, req->low,
                               req->high, req->type, sd )))
    {
        if (get_error() == STATUS_OBJECT_NAME_EXISTS)
            reply->handle = alloc_handle( current->process, msync, req->access, objattr->attributes );
        else
            reply->handle = alloc_handle_no_access_check( current->process, msync,
                                                          req->access, objattr->attributes );

        reply->shm_idx = msync->shm_idx;
        reply->type = msync->type;
        release_object( msync );
    }

    if (root) release_object( root );
}

DECL_HANDLER(open_msync)
{
    struct unicode_str name = get_req_unicode_str();

    reply->handle = open_object( current->process, req->rootdir, req->access,
                                 &msync_ops, &name, req->attributes );

    if (reply->handle)
    {
        struct msync *msync;

        if (!(msync = (struct msync *)get_handle_obj( current->process, reply->handle,
                                                      0, &msync_ops )))
            return;

        if (!type_matches( req->type, msync->type ))
        {
            set_error( STATUS_OBJECT_TYPE_MISMATCH );
            release_object( msync );
            return;
        }

        reply->type = msync->type;
        reply->shm_idx = msync->shm_idx;
        release_object( msync );
    }
}

/* Retrieve the index of a shm section which will be signaled by the server. */
DECL_HANDLER(get_msync_idx)
{
    struct object *obj;
    enum msync_type type;

    if (!(obj = get_handle_obj( current->process, req->handle, SYNCHRONIZE, NULL )))
        return;

    if (obj->ops->get_msync_idx)
    {
        reply->shm_idx = obj->ops->get_msync_idx( obj, &type );
        reply->type = type;
    }
    else
    {
        if (debug_level)
        {
            fprintf( stderr, "%04x: msync: can't wait on object: ", current->id );
            obj->ops->dump( obj, 0 );
        }
        set_error( STATUS_NOT_IMPLEMENTED );
    }

    release_object( obj );
}

DECL_HANDLER(get_msync_apc_idx)
{
    reply->shm_idx = current->msync_apc_idx;
}
