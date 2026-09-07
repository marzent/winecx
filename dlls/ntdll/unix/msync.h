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
extern void msync_init(void);
extern void msync_close( int obj );

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

extern NTSTATUS msync_release_semaphore_obj( int obj, ULONG count, ULONG *prev_count );
extern NTSTATUS msync_query_semaphore_obj( int obj, SEMAPHORE_BASIC_INFORMATION *info );
extern NTSTATUS msync_set_event_obj( int obj, LONG *prev_state );
extern NTSTATUS msync_reset_event_obj( int obj, LONG *prev_state );
extern NTSTATUS msync_pulse_event_obj( int obj, LONG *prev_state );
extern NTSTATUS msync_query_event_obj( int obj, EVENT_BASIC_INFORMATION *info );
extern NTSTATUS msync_release_mutex_obj( int obj, LONG *prev_count );
extern NTSTATUS msync_query_mutex_obj( int obj, MUTANT_BASIC_INFORMATION *info );
extern NTSTATUS msync_wait_objs( const DWORD count, const int *objs, BOOLEAN wait_any,
                                 int alert_obj, const LARGE_INTEGER *timeout );

#endif /* __APPLE__ */
