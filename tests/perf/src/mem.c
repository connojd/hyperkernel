/*
 * Bareflank Hyperkernel
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>






/*
 * argv[0] = npages
 * argv[1] = pagesz
 * addr = 0x40000000UL
 */

int
main(int argc, const char *argv[])
{
    if (argc != 3) {
        printf("Need args: filename, npages, pagesz\n");
        return 22;
    }

    for (int i = 0; i < argc; i++) {
        printf("    argv[%d] = %s\n", i, argv[i]);
    }

    long int npages = strtol(argv[1], NULL, 0);
    long int pagesz = strtol(argv[2], NULL, 0);
    char *addr = 0x40000000UL;

    for (int i = 0; i < npages; i++) {
        *(addr + i * pagesz) = 'h';
    }
//    *(ptr + 0x200000UL) = 'u';
//    *(ptr + 0x400000UL) = 'g';
//    *(ptr + 0x600000UL) = 'e';
//    printf("    huge[0] = %c\n", *ptr);
//    printf("    huge[1] = %c\n", *(ptr + 0x200000UL));
//    printf("    huge[2] = %c\n", *(ptr + 0x400000UL));
//    printf("    huge[3] = %c\n", *(ptr + 0x600000UL));

    return 0;
}
