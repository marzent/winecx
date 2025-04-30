/*
 * Mac driver window surface implementation
 *
 * Copyright 1993, 1994, 2011 Alexandre Julliard
 * Copyright 2006 Damjan Jovanovic
 * Copyright 2012, 2013 Ken Thomases for CodeWeavers, Inc.
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

#include "macdrv.h"
#include "winuser.h"

WINE_DEFAULT_DEBUG_CHANNEL(bitblt);

static inline int get_dib_stride(int width, int bpp)
{
    return ((width * bpp + 31) >> 3) & ~3;
}

static inline int get_dib_image_size(const BITMAPINFO *info)
{
    return get_dib_stride(info->bmiHeader.biWidth, info->bmiHeader.biBitCount)
        * abs(info->bmiHeader.biHeight);
}


struct macdrv_window_surface
{
    struct window_surface   header;
    macdrv_window           window;
    CGDataProviderRef       provider;
    IOSurfaceRef            front_buffer;
    IOSurfaceRef            back_buffer;
    BOOL                    shape_changed;
};

static struct macdrv_window_surface *get_mac_surface(struct window_surface *surface);

static CGDataProviderRef data_provider_create(size_t size, void **bits)
{
    CGDataProviderRef provider;
    CFMutableDataRef data;

    if (!(data = CFDataCreateMutable(kCFAllocatorDefault, size))) return NULL;
    CFDataSetLength(data, size);

    if ((provider = CGDataProviderCreateWithCFData(data)))
        *bits = CFDataGetMutableBytePtr(data);
    CFRelease(data);

    return provider;
}

/***********************************************************************
 *              macdrv_surface_set_clip
 */
static void macdrv_surface_set_clip(struct window_surface *window_surface, const RECT *rects, UINT count)
{
}

/***********************************************************************
 *              macdrv_surface_flush
 */
static BOOL macdrv_surface_flush(struct window_surface *window_surface, const RECT *rect, const RECT *dirty,
                                 const BITMAPINFO *color_info, const void *color_bits, BOOL shape_changed,
                                 const BITMAPINFO *shape_info, const void *shape_bits)
{
    struct macdrv_window_surface *surface = get_mac_surface(window_surface);
    CGImageAlphaInfo alpha_info = (window_surface->alpha_mask ? kCGImageAlphaPremultipliedFirst : kCGImageAlphaNoneSkipFirst);
    CGColorSpaceRef colorspace;
    CGImageRef image;
    IOSurfaceRef io_surface = surface->back_buffer;

    surface->back_buffer = surface->front_buffer;
    surface->front_buffer = io_surface;

    {
        vImage_Buffer src = {
            .data = color_bits,
            .height = IOSurfaceGetHeight(io_surface),
            .width = IOSurfaceGetWidth(io_surface),
            .rowBytes = IOSurfaceGetBytesPerRow(io_surface),
        };
        vImage_Buffer dst = {
            .data = IOSurfaceGetBaseAddress(io_surface),
            .height = IOSurfaceGetHeight(io_surface),
            .width = IOSurfaceGetWidth(io_surface),
            .rowBytes = IOSurfaceGetBytesPerRow(io_surface),
        };
        vImageSelectChannels_ARGB8888(&src, &dst, &dst, 0x8 | 0x4 | 0x2, kvImageNoFlags);
    }

    if (shape_changed || surface->shape_changed)
    {
        surface->shape_changed = FALSE;

        if (!shape_bits)
        {
            Pixel_8888 alpha1 = { 0, 0, 0, 255 };
            vImage_Buffer dst = {
                .data = IOSurfaceGetBaseAddress(io_surface),
                .height = IOSurfaceGetHeight(io_surface),
                .width = IOSurfaceGetWidth(io_surface),
                .rowBytes = IOSurfaceGetBytesPerRow(io_surface),
            };
            vImageOverwriteChannelsWithPixel_ARGB8888(alpha1, &dst, &dst, 0x1, kvImageNoFlags);
        }
        else
        {
            const BYTE *src = shape_bits;
            BYTE *dst = IOSurfaceGetBaseAddress(io_surface);
            UINT x, y;
            UINT src_row_bytes = shape_info->bmiHeader.biSizeImage / abs(shape_info->bmiHeader.biHeight);

            for (y = 0; y < IOSurfaceGetHeight(io_surface); y++)
            {
                const BYTE *src_row = src + y * src_row_bytes;
                BYTE *dst_row = dst + y * IOSurfaceGetBytesPerRow(io_surface);
                for (x = 0; x < IOSurfaceGetWidth(io_surface); x++)
                {
                    BYTE bit = (src_row[x / 8] >> (7 - (x % 8))) & 1;
                    dst_row[x * 4] = bit ? 0 : 255;
                }
            }
        }
    }

    macdrv_window_set_io_surface(surface->window, io_surface, cgrect_from_rect(*rect), cgrect_from_rect(*dirty));

    if (shape_changed)
    {
        surface->shape_changed = TRUE;

        if (!shape_bits)
            macdrv_window_shape_changed(surface->window, FALSE);
        else
            macdrv_window_shape_changed(surface->window, TRUE);
    }

    return TRUE;
}

/***********************************************************************
 *              macdrv_surface_destroy
 */
static void macdrv_surface_destroy(struct window_surface *window_surface)
{
    struct macdrv_window_surface *surface = get_mac_surface(window_surface);

    TRACE("freeing %p\n", surface);
    CGDataProviderRelease(surface->provider);
    CFRelease(surface->back_buffer);
    CFRelease(surface->front_buffer);
}

static const struct window_surface_funcs macdrv_surface_funcs =
{
    macdrv_surface_set_clip,
    macdrv_surface_flush,
    macdrv_surface_destroy,
};

static struct macdrv_window_surface *get_mac_surface(struct window_surface *surface)
{
    if (!surface || surface->funcs != &macdrv_surface_funcs) return NULL;
    return (struct macdrv_window_surface *)surface;
}

/***********************************************************************
 *              create_surface
 */
static struct window_surface *create_surface(HWND hwnd, macdrv_window window, const RECT *rect)
{
    struct macdrv_window_surface *surface;
    int width = rect->right - rect->left, height = rect->bottom - rect->top;
    DWORD window_background;
    D3DKMT_CREATEDCFROMMEMORY desc = {.Format = D3DDDIFMT_A8R8G8B8};
    char buffer[FIELD_OFFSET(BITMAPINFO, bmiColors[256])];
    BITMAPINFO *info = (BITMAPINFO *)buffer;
    struct window_surface *window_surface;
    CGDataProviderRef provider;
    HBITMAP bitmap = 0;
    UINT status;
    void *bits;
    IOSurfaceRef io_surface1, io_surface2;

    memset(info, 0, sizeof(*info));
    info->bmiHeader.biSize        = sizeof(info->bmiHeader);
    info->bmiHeader.biWidth       = width;
    info->bmiHeader.biHeight      = -height; /* top-down */
    info->bmiHeader.biPlanes      = 1;
    info->bmiHeader.biBitCount    = 32;
    info->bmiHeader.biSizeImage   = get_dib_image_size(info);
    info->bmiHeader.biCompression = BI_RGB;

    if (!(provider = data_provider_create(info->bmiHeader.biSizeImage, &bits))) return NULL;
    window_background = macdrv_window_background_color();

    {
        CFDictionaryRef properties;
        CFStringRef keys[] = { kIOSurfaceWidth, kIOSurfaceHeight, kIOSurfaceBytesPerElement, kIOSurfacePixelFormat };
        CFNumberRef values[4];
        uint32_t surfaceWidth = info->bmiHeader.biWidth;
        uint32_t surfaceHeight = abs(info->bmiHeader.biHeight);
        uint32_t surfaceBytesPerElement = 4;
        uint32_t surfacePixelFormat = 'BGRA';
        
        values[0] = CFNumberCreate(NULL, kCFNumberSInt32Type, &surfaceWidth);
        values[1] = CFNumberCreate(NULL, kCFNumberSInt32Type, &surfaceHeight);
        values[2] = CFNumberCreate(NULL, kCFNumberSInt32Type, &surfaceBytesPerElement);
        values[3] = CFNumberCreate(NULL, kCFNumberSInt32Type, &surfacePixelFormat);

        properties = CFDictionaryCreate(NULL, (void **)keys, (void **)values, ARRAY_SIZE(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        io_surface1 = IOSurfaceCreate(properties);
        io_surface2 = IOSurfaceCreate(properties);
        CFRelease(properties);

        memset_pattern4(IOSurfaceGetBaseAddress(io_surface1), &window_background, info->bmiHeader.biSizeImage);
        memset_pattern4(IOSurfaceGetBaseAddress(io_surface2), &window_background, info->bmiHeader.biSizeImage);
    }

    window_background &= 0x00ffffff;
    memset_pattern4(bits, &window_background, info->bmiHeader.biSizeImage);

    /* wrap the data in a HBITMAP so we can write to the surface pixels directly */
    desc.Width = info->bmiHeader.biWidth;
    desc.Height = abs(info->bmiHeader.biHeight);
    desc.Pitch = info->bmiHeader.biSizeImage / abs(info->bmiHeader.biHeight);
    desc.pMemory = bits;
    desc.hDeviceDc = NtUserGetDCEx(hwnd, 0, DCX_CACHE | DCX_WINDOW);
    if ((status = NtGdiDdDDICreateDCFromMemory(&desc)))
        ERR("Failed to create HBITMAP, status %#x\n", status);
    else
    {
        bitmap = desc.hBitmap;
        NtGdiDeleteObjectApp(desc.hDc);
    }
    if (desc.hDeviceDc) NtUserReleaseDC(hwnd, desc.hDeviceDc);

    if (!(window_surface = window_surface_create(sizeof(*surface), &macdrv_surface_funcs, hwnd, rect, info, bitmap)))
    {
        if (bitmap) NtGdiDeleteObjectApp(bitmap);
        CGDataProviderRelease(provider);
    }
    else
    {
        surface = get_mac_surface(window_surface);
        surface->window = window;
        surface->provider = provider;
        surface->front_buffer = io_surface1;
        surface->back_buffer = io_surface2;
        surface->shape_changed = FALSE;
    }

    return window_surface;
}


/***********************************************************************
 *              CreateWindowSurface   (MACDRV.@)
 */
BOOL macdrv_CreateWindowSurface(HWND hwnd, BOOL layered, const RECT *surface_rect, struct window_surface **surface)
{
    struct window_surface *previous;
    struct macdrv_win_data *data;

    TRACE("hwnd %p, layered %u, surface_rect %s, surface %p\n", hwnd, layered, wine_dbgstr_rect(surface_rect), surface);

    if ((previous = *surface) && previous->funcs == &macdrv_surface_funcs) return TRUE;
    if (!(data = get_win_data(hwnd))) return TRUE; /* use default surface */
    if (previous) window_surface_release(previous);

    if (layered)
    {
        data->layered = TRUE;
        data->ulw_layered = TRUE;
    }

    *surface = create_surface(hwnd, data->cocoa_window, surface_rect);

    release_win_data(data);
    return TRUE;
}
