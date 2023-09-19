/*
 * futex-based synchronization objects
 *
 * Copyright (C) 2018 Zebediah Figura
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
#ifdef HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "handle.h"
#include "request.h"
#include "msync.h"

struct futex_wait_block
{
    int *addr;
    int pad;
    int val;
};

static inline int futex_wait_multiple( const struct futex_wait_block *futexes,
        int count, const struct timespec *timeout )
{
    return 0;
}

int do_msync(void)
{
#ifdef __linux__
    static int do_msync_cached = -1;

    if (do_msync_cached == -1)
    {
        static const struct timespec zero;
        futex_wait_multiple( NULL, 0, &zero );
        do_msync_cached = getenv("WINEMSYNC") && atoi(getenv("WINEMSYNC")) && errno != ENOSYS;
    }

    return do_msync_cached;
#else
    return 0;
#endif
}

static char shm_name[29];
static int shm_fd;
static off_t shm_size;
static void **shm_addrs;
static int shm_addrs_size;  /* length of the allocated shm_addrs array */
static long pagesize;

static int is_msync_initialized;

static void shm_cleanup(void)
{
    close( shm_fd );
    if (shm_unlink( shm_name ) == -1)
        perror( "shm_unlink" );
}

void msync_init(void)
{
    struct stat st;

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

    shm_addrs = calloc( 128, sizeof(shm_addrs[0]) );
    shm_addrs_size = 128;

    shm_size = pagesize;
    if (ftruncate( shm_fd, shm_size ) == -1)
        perror( "ftruncate" );

    is_msync_initialized = 1;

    fprintf( stderr, "msync: up and running.\n" );

    atexit( shm_cleanup );
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

/* FIXME: This is rather inefficient... */
static unsigned int shm_idx_counter = 1;

unsigned int msync_alloc_shm( int low, int high )
{
#ifdef __linux__
    int shm_idx;
    int *shm;

    /* this is arguably a bit of a hack, but we need some way to prevent
     * allocating shm for the master socket */
    if (!is_msync_initialized)
        return 0;

    shm_idx = shm_idx_counter++;

    while (shm_idx * 8 >= shm_size)
    {
        /* Better expand the shm section. */
        shm_size += pagesize;
        if (ftruncate( shm_fd, shm_size ) == -1)
        {
            fprintf( stderr, "msync: couldn't expand %s to size %jd: ",
                shm_name, shm_size );
            perror( "ftruncate" );
        }
    }

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
#ifdef __linux__
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

static inline int futex_wake( int *addr, int val )
{
    return 0;
}

/* shm layout for events or event-like objects. */
struct msync_event
{
    int signaled;
    int unused;
};

void msync_wake_futex( unsigned int shm_idx )
{
    struct msync_event *event;

    if (debug_level)
        fprintf( stderr, "msync_wake_futex: index %u\n", shm_idx );

    if (!shm_idx)
        return;

    event = get_shm( shm_idx );
    if (!__atomic_exchange_n( &event->signaled, 1, __ATOMIC_SEQ_CST ))
        futex_wake( &event->signaled, INT_MAX );
}

void msync_wake_up( struct object *obj )
{
    enum msync_type type;

    if (debug_level)
        fprintf( stderr, "msync_wake_up: object %p\n", obj );

    if (obj->ops->get_msync_idx)
        msync_wake_futex( obj->ops->get_msync_idx( obj, &type ) );
}

void msync_clear_futex( unsigned int shm_idx )
{
    struct msync_event *event;

    if (debug_level)
        fprintf( stderr, "msync_clear_futex: index %u\n", shm_idx );

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
        msync_clear_futex( obj->ops->get_msync_idx( obj, &type ) );
}

void msync_set_event( struct msync *msync )
{
    struct msync_event *event = get_shm( msync->shm_idx );
    assert( msync->obj.ops == &msync_ops );

    if (!__atomic_exchange_n( &event->signaled, 1, __ATOMIC_SEQ_CST ))
        futex_wake( &event->signaled, INT_MAX );
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
            futex_wake( &mutex->tid, INT_MAX );
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
