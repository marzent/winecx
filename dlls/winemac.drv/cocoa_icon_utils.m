/*
 * MACDRV Cocoa icon utilities
 *
 * Copyright 2025 Tim Clem for CodeWeavers Inc.
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

/* CW Hack 25964 */

#include "config.h"
#import "cocoa_icon_utils.h"

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"


@implementation WineIconUtils

+ (double) percentOfNonTransparentPixelsAlongEdgeOfImage:(NSImage *)image
{
    static const int edgeSize = 50;  /* @ 1024x1024 */

    CGContextRef ctx;
    NSRect fullRect = NSMakeRect(0, 0, 1024, 1024);
    size_t bitsPerPixel = 8;
    size_t bytesPerRow = bitsPerPixel * fullRect.size.width;
    uint8_t *data = calloc(bytesPerRow * fullRect.size.height, sizeof(uint8_t));

    if (!data)
        return 0;

    ctx = CGBitmapContextCreate(data, fullRect.size.width, fullRect.size.height, bitsPerPixel, bytesPerRow, NULL, (CGBitmapInfo)kCGImageAlphaOnly);
    NSGraphicsContext.currentContext = [NSGraphicsContext graphicsContextWithCGContext:ctx flipped:NO];

    /* Mask the image to a frame around the edges. */
    [NSColor.whiteColor set];
    NSFrameRectWithWidth(fullRect, edgeSize);

    [image drawInRect:fullRect
             fromRect:NSZeroRect
            operation:NSCompositingOperationDestinationIn
             fraction:1.0
       respectFlipped:YES
                hints:nil];

    NSGraphicsContext.currentContext = nil;

    size_t nonTransparentPixels = 0;
    for (size_t y = 0; y < fullRect.size.height; y++)
    {
        for(size_t x = 0; x < fullRect.size.width; x++)
        {
            if (data[x + y * bytesPerRow] != 0)
                nonTransparentPixels++;
        }
    }

    size_t maxNonTransparentPixels = (size_t)((edgeSize * fullRect.size.width * 2) + (edgeSize * fullRect.size.height * 2) - (edgeSize * edgeSize * 4));
    double pct = nonTransparentPixels / (double)maxNonTransparentPixels;

    CGContextRelease(ctx);
    free(data);

    return pct;
}

+ (NSImage *)roundrectMaskImage
{
    static NSImage *image = nil;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        const char *cx_root = getenv("CX_ROOT");
        if (!cx_root || !cx_root[0])
            return;

        NSURL *url = [NSURL fileURLWithFileSystemRepresentation:cx_root isDirectory:YES relativeToURL:nil];
        url = [[url URLByDeletingLastPathComponent] URLByDeletingLastPathComponent];
        url = [url URLByAppendingPathComponent:@"Resources" isDirectory:YES];
        url = [url URLByAppendingPathComponent:@"app-icon-roundrect-mask.png"];

        image = [[NSImage alloc] initWithContentsOfURL:url];
    });

    return image;
}

+ (NSImage *) maskIconToRoundRect:(NSImage *)icon destinationDimension:(NSUInteger)destDim
{
    /* Assumes the mask image is 1024x1024, with the roundrect itself at
       (100, 100) and 824x824. */
    static const NSRect unscaledContentRect = {{100, 100}, {824, 824}};

    /* If the edges of the icon have greater than the minimum percent
       filled and less than the maximum, the icon will be resized to
       fall in the center of the mask by insetting the destination
       rect by unscaledResizeInset. Otherwise we apply the mask to
       the whole icon without resizing it first. */
    static const double edgeContentPctNoResizeMin = 0.05;
    static const double edgeContentPctNoResizeMax = 0.9;
    static const int unscaledResizeInset = 80;  /* @ 1024x1024; scaled later */

    /* Settings for the shadow drawn under the roundrect. These are at
       1024x1024; they are scaled appropriately later. */
    static const CGFloat unscaledShadowHeight = 5;
    static const CGFloat unscaledShadowBlurRadius = 25;

    NSImage *maskImg = [self roundrectMaskImage];
    if (!maskImg)
        return nil;

    NSRect fullDestRect = NSMakeRect(0, 0, destDim, destDim);

    NSRect iconDestinationRect = unscaledContentRect;
    double edgeContentPct = [self percentOfNonTransparentPixelsAlongEdgeOfImage:icon];
    if (edgeContentPct > edgeContentPctNoResizeMin && edgeContentPct < edgeContentPctNoResizeMax)
        iconDestinationRect = NSInsetRect(iconDestinationRect, unscaledResizeInset, unscaledResizeInset);

    /* Scale our destination rect to the target size. */
    CGFloat scaleFactor = destDim / 1024.0;
    iconDestinationRect.origin.x *= scaleFactor;
    iconDestinationRect.origin.y *= scaleFactor;
    iconDestinationRect.size.width *= scaleFactor;
    iconDestinationRect.size.height *= scaleFactor;

    /* Mask the icon to the roundrect. */
    NSImage *masked = [[NSImage alloc] initWithSize:fullDestRect.size];
    [masked lockFocusFlipped:NO];
    [maskImg drawInRect:fullDestRect];

    [icon drawInRect:iconDestinationRect
            fromRect:NSZeroRect
           operation:NSCompositingOperationSourceIn
            fraction:1.0
      respectFlipped:YES
               hints:@{ NSImageHintInterpolation: @(NSImageInterpolationHigh) }];
    [masked unlockFocus];

    /* Now draw the roundrect with a shadow, and lay the masked icon on top. */
    NSImage *composited = [[NSImage alloc] initWithSize:fullDestRect.size];
    [composited lockFocusFlipped:NO];

    NSShadow *maskShadow = [NSShadow new];
    maskShadow.shadowOffset = NSMakeSize(0, -unscaledShadowHeight * scaleFactor);
    maskShadow.shadowBlurRadius = unscaledShadowBlurRadius * scaleFactor;

    [NSGraphicsContext saveGraphicsState];
    [maskShadow set];
    [maskImg drawInRect:fullDestRect];
    [NSGraphicsContext restoreGraphicsState];

    [masked drawInRect:fullDestRect
              fromRect:NSZeroRect
             operation:NSCompositingOperationSourceOver
              fraction:1.0
        respectFlipped:YES
                 hints:nil];

    [composited unlockFocus];

    [masked release];

    return composited;
}

+ (NSImage *) maskedAppIconFromCGImages:(NSArray *)images
{
    /* The dimensions of image we will generate for an app icon. The largest
       available Windows icon will be composited into an image of this size. */
    static const NSUInteger appIconSize = 512;

    if (images.count == 0)
        return nil;

    NSArray *sortedImages = [images sortedArrayUsingComparator:^(id a, id b) {
        size_t ha = CGImageGetHeight((CGImageRef)a), hb = CGImageGetHeight((CGImageRef)b);
        if (ha == hb) return NSOrderedSame;
        return ha > hb ? NSOrderedDescending : NSOrderedAscending;
    }];

    NSImage *biggestImage = [[NSImage alloc] initWithCGImage:(CGImageRef)sortedImages.lastObject
                                                        size:NSZeroSize];

    NSImage *res = [self maskIconToRoundRect:biggestImage destinationDimension:appIconSize];
    [biggestImage release];
    return [res autorelease];
}

@end
