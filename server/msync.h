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

extern int do_msync(void);
extern void msync_init_shm(void);
extern void msync_init(void);

#ifdef __APPLE__

enum msync_type
{
    MSYNC_SEMAPHORE = 1,
    MSYNC_AUTO_EVENT,
    MSYNC_MANUAL_EVENT,
    MSYNC_MUTEX,
    MSYNC_AUTO_SERVER,
    MSYNC_MANUAL_SERVER,
};

struct msync
{
    unsigned int    shm_idx;
    struct list     mutex_entry;
};

extern struct msync *create_msync( int low, int high, enum msync_type type );
extern void msync_grab_object( struct msync *msync );
extern void msync_destroy( struct msync *msync );
extern void msync_set_event( struct msync *msync );
extern void msync_reset_event( struct msync *msync );
extern void msync_abandon_mutexes( thread_id_t tid );

#endif /* __APPLE__ */
