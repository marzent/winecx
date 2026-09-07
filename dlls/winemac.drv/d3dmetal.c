/*
 * Mac graphics driver hooks used by D3DMetal (part of the Apple Game Porting Toolkit)
 *
 * Copyright 2023 Brendan Shanks for CodeWeavers, Inc.
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

#include "config.h"

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "macdrv.h"
#include "shellapi.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(macdrv_d3dmtl);

typedef LONG LSTATUS;

struct macdrv_functions_t
{
    void (*macdrv_init_display_devices)(BOOL);
    struct d3dmetal_macdrv_win_data* (*get_win_data)(HWND hwnd);
    void (*release_win_data)(struct d3dmetal_macdrv_win_data *data);
    macdrv_window(*macdrv_get_cocoa_window)(HWND hwnd, BOOL require_on_screen);
    macdrv_metal_device (*macdrv_create_metal_device)(void);
    void (*macdrv_release_metal_device)(macdrv_metal_device d);
    macdrv_metal_view (*macdrv_view_create_metal_view)(macdrv_view v, macdrv_metal_device d);
    macdrv_metal_layer (*macdrv_view_get_metal_layer)(macdrv_metal_view v);
    void (*macdrv_view_release_metal_view)(macdrv_metal_view v);
    void (*on_main_thread)(dispatch_block_t b);
    LSTATUS(WINAPI*RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, BYTE*, LPDWORD);
    LSTATUS(WINAPI*RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
    LSTATUS(WINAPI*RegOpenKeyExA)(HKEY, LPCSTR, DWORD, DWORD, HKEY*);
    LSTATUS(WINAPI*RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, HKEY*, LPDWORD);
    LSTATUS(WINAPI*RegCloseKey)(HKEY);
    BOOL(WINAPI*EnumDisplayMonitors)(HDC,LPRECT,MONITORENUMPROC,LPARAM);
    BOOL(WINAPI*GetMonitorInfoA)(HMONITOR,LPMONITORINFO);
    BOOL(WINAPI*AdjustWindowRectEx)(LPRECT,DWORD,BOOL,DWORD);
    LONG_PTR(WINAPI*GetWindowLongPtrW)(HWND,int);
    BOOL(WINAPI*GetWindowRect)(HWND,LPRECT);
    BOOL(WINAPI*MoveWindow)(HWND,int,int,int,int,BOOL);
    BOOL(WINAPI*SetWindowPos)(HWND,HWND,int,int,int,int,UINT);
    INT(WINAPI*GetSystemMetrics)(INT);
    LONG_PTR(WINAPI*SetWindowLongPtrW)(HWND,INT,LONG_PTR);
};
C_ASSERT(sizeof(struct macdrv_functions_t) == 192);

struct d3dmetal_macdrv_view_data
{
    struct client_surface *client;
    macdrv_metal_layer metal_layer;
};

/* macdrv private window data expected by D3DMetal */
struct d3dmetal_macdrv_win_data
{
    char pad_hwnd[sizeof(HWND)];
    char pad_cocoa_window[sizeof(macdrv_window)];
    char pad_cocoa_view[sizeof(macdrv_view)];
    struct d3dmetal_macdrv_view_data *client_cocoa_view;
    char pad_window_rect[sizeof(RECT)];
    char pad_whole_rect[sizeof(RECT)];
    char pad_client_rect[sizeof(RECT)];
    char pad_pixel_format[sizeof(int)];
    char pad_color_key[sizeof(COLORREF)];
    char pad_drag_event[sizeof(HANDLE)];
    char pad_flags[sizeof(unsigned int)];  /* bitfields */
    void *padding[2];
};

C_ASSERT(sizeof(struct d3dmetal_macdrv_win_data) == 120);

static void my_macdrv_init_display_devices(BOOL p1)
{
    TRACE("macdrv_init_display_devices %d - no-op\n", p1);
}

static struct d3dmetal_macdrv_win_data *my_get_win_data(HWND hwnd)
{
    struct client_surface *client;
    struct macdrv_client_surface *surface;
    struct d3dmetal_macdrv_win_data *d3dm_data;
    TRACE("get_win_data %p\n", hwnd);

    client = get_unused_client_surface( hwnd, 0, FALSE );
    surface = impl_from_client_surface(client);
    if (!macdrv_client_surface_acquire_metal_swapchain(surface))
    {
        client_surface_release(client);
        return NULL;
    }

    d3dm_data = calloc(1, sizeof(*d3dm_data));
    d3dm_data->client_cocoa_view = calloc(1, sizeof(*d3dm_data->client_cocoa_view));
    d3dm_data->client_cocoa_view->client = client;
    d3dm_data->client_cocoa_view->metal_layer = macdrv_swapchain_get_layer(surface->metal_swapchain);

    use_window_client_surface(client, TRUE);
    return d3dm_data;
}

static void my_release_win_data(struct d3dmetal_macdrv_win_data *data)
{
    TRACE("release_win_data %p\n", data);

    if (!data)
        return;

    free(data);
}

static macdrv_window my_macdrv_get_cocoa_window(HWND hwnd, BOOL require_on_screen)
{
    TRACE("macdrv_get_cocoa_window %p %d\n", hwnd, require_on_screen);
    return macdrv_get_cocoa_window(hwnd, require_on_screen);
}

static macdrv_metal_device my_macdrv_create_metal_device(void)
{
    TRACE("macdrv_create_metal_device no-op\n");
    return NULL;
}

static void my_macdrv_release_metal_device(macdrv_metal_device d)
{
    TRACE("macdrv_release_metal_device no-op%p\n", d);
}

static macdrv_metal_view my_macdrv_view_create_metal_view(macdrv_view v, macdrv_metal_device d)
{
    TRACE("macdrv_view_create_metal_view %p %p\n", v, d);
    return (macdrv_metal_view)v;
}

static macdrv_metal_layer my_macdrv_view_get_metal_layer(macdrv_metal_view v)
{
    struct d3dmetal_macdrv_view_data *view_data = (struct d3dmetal_macdrv_view_data *)v;
    TRACE("macdrv_view_get_metal_layer %p\n", v);
    return view_data->metal_layer;
}

static void my_macdrv_view_release_metal_view(macdrv_metal_view v)
{
    struct d3dmetal_macdrv_view_data *view_data = (struct d3dmetal_macdrv_view_data *)v;
    TRACE("macdrv_view_release_metal_view %p\n", v);

    if (!view_data)
        return;
    client_surface_release(view_data->client);
    free(view_data);
}

static void my_OnMainThread(dispatch_block_t b)
{
    FIXME("OnMainThread %p - unimplemented\n", b);
}


static LSTATUS WINAPI my_RegQueryValueExA(HKEY p1, LPCSTR p2, LPDWORD p3, LPDWORD p4, BYTE* p5, LPDWORD p6)
{
    FIXME("RegQueryValueExA %p %s %p %p %p %p - unimplemented\n", p1, p2, p3, p4, p5, p6);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static LSTATUS WINAPI my_RegSetValueExA(HKEY p1, LPCSTR p2, DWORD p3, DWORD p4, const BYTE* p5, DWORD p6)
{
    FIXME("RegSetValueExA %p %s(%p) %d %p %d - unimplemented\n", p1, p2, p2, p4, p5, p6);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static LSTATUS WINAPI my_RegOpenKeyExA(HKEY p1, LPCSTR p2, DWORD p3, DWORD p4, HKEY* p5)
{
    FIXME("RegOpenKeyExA %p %s - unimplemented\n", p1, p2);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static LSTATUS WINAPI my_RegCreateKeyExA(HKEY p1, LPCSTR p2, DWORD p3, LPSTR p4, DWORD p5, DWORD p6, LPSECURITY_ATTRIBUTES p7, HKEY* p8, LPDWORD p9)
{
    FIXME("RegCreateKeyExA %p %s - unimplemented\n", p1, p2);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static LSTATUS WINAPI my_RegCloseKey(HKEY hkey)
{
    FIXME("RegCloseKey %p - unimplemented\n", hkey);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static BOOL WINAPI my_EnumDisplayMonitors(HDC h, LPRECT p2, MONITORENUMPROC p3, LPARAM p4)
{
    FIXME("EnumDisplayMonitors %p %p %p %ld - unimplemented\n", h, p2, p3, p4);
    return 0;
}

static BOOL WINAPI my_GetMonitorInfoA(HMONITOR monitor, LPMONITORINFO info)
{
    FIXME("GetMonitorInfoA %p %p - unimplemented\n", monitor, info);
    return 0;
}

static BOOL WINAPI my_AdjustWindowRectEx(LPRECT p1,DWORD p2,BOOL p3,DWORD p4)
{
    FIXME("AdjustWindowRectEx %p %u %d %u - unimplemented\n", p1, p2, p3, p4);
    return 0;
}

static LONG_PTR WINAPI my_GetWindowLongPtrW(HWND h,int nIndex)
{
    FIXME("GetWindowLongPtrW %p - unimplemented\n", h);
    return 0;
}

static BOOL WINAPI my_GetWindowRect(HWND h, LPRECT rect)
{
    FIXME("GetWindowRect %p %p - unimplemented\n", h, rect);
    return 0;
}

static BOOL WINAPI my_MoveWindow(HWND h, int X,int Y,int nWidth,int nHeight,BOOL bRepaint)
{
    FIXME("MoveWindow %p %d %d %d %d %d - unimplemented\n", h, X, Y, nWidth, nHeight, bRepaint);
    return 0;
}

static BOOL WINAPI my_SetWindowPos(HWND h,HWND h2,int x,int y,int cx,int cy,UINT flags)
{
    FIXME("SetWindowPos %p %p %d %d %d %d %u - unimplemented\n", h, h2, x, y, cx, cy, flags);
    return 0;
}

static INT WINAPI my_GetSystemMetrics(INT index)
{
    FIXME("GetSystemMetrics %d - unimplemented\n", index);
    return 0;
}

static LONG_PTR WINAPI my_SetWindowLongPtrW(HWND hwnd, INT offset, LONG_PTR newval)
{
    FIXME("SetWindowLongPtrW %p %d %ld - unimplemented\n", hwnd, offset, newval);
    return 0;
}

DECLSPEC_EXPORT struct macdrv_functions_t macdrv_functions =
{
    &my_macdrv_init_display_devices,
    &my_get_win_data,
    &my_release_win_data,
    &my_macdrv_get_cocoa_window,
    &my_macdrv_create_metal_device,
    &my_macdrv_release_metal_device,
    &my_macdrv_view_create_metal_view,
    &my_macdrv_view_get_metal_layer,
    &my_macdrv_view_release_metal_view,
    &my_OnMainThread,
    &my_RegQueryValueExA,
    &my_RegSetValueExA,
    &my_RegOpenKeyExA,
    &my_RegCreateKeyExA,
    &my_RegCloseKey,
    &my_EnumDisplayMonitors,
    &my_GetMonitorInfoA,
    &my_AdjustWindowRectEx,
    &my_GetWindowLongPtrW,
    &my_GetWindowRect,
    &my_MoveWindow,
    &my_SetWindowPos,
    &my_GetSystemMetrics,
    &my_SetWindowLongPtrW,
};

DECLSPEC_EXPORT void d3d_present_client_surface(macdrv_metal_view v)
{
    struct d3dmetal_macdrv_view_data *view_data = (struct d3dmetal_macdrv_view_data *)v;
    TRACE("d3d_present_client_surface %p\n", v);
    client_surface_present(view_data->client);
}

