/**
* ELF Analysis Library Configuration
*
* Copyright (C) 2013 Aaron Clovsky <pelvicthrustman@gmail.com>
*
* This file is part of PS2rd, the PS2 remote debugger.
*
* PS2rd is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* PS2rd is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with PS2rd.  If not, see <http://www.gnu.org/licenses/>.
*
* $Id$
*/

//#define ENTRY(function_name, length, jal_count, jal_scope, j_type, jal_address, jal_relative_offset, jal_relative_offset_tolerance, target_offset, target_jal_offset, pattern, mask);

#ifndef ELF_MODULE_DEFINITIONS
#define ELF_MODULE_DEFINITIONS

#define FOREACH_ELF_FUNCTION_ID(ENTRY)                             \
	ENTRY(0, 1, 0, 0, 0, 0, 0, -1, 0, {{ 0x0 },{ 0x0 }})           \
	                                                               \
	ENTRY(memcpy, 10, 0, 0, 0, 0, 0, -1, 0,                        \
	{{0x0080402d, 0x2cc20020, 0x1440001c, 0x0100182d, 0x00a81025,  \
	  0x3042000f, 0x54400019, 0x24c6ffff, 0x0100382d, 0x78a30000 },\
	{ 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,  \
	  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}})\
                                                                   \
	ENTRY(sceSifSendCmd, 10, 1, 15, 0, -88, 8, -1, 0,              \
	{{0x00c0102d, 0x00e0182d, 0x0100582d, 0x27bdfff0, 0x0120502d,  \
	  0x00a0302d, 0xffbf0000, 0x0040382d, 0x0060402d, 0x0160482d },\
	{ 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,  \
	  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}})\
                                                                   \
	ENTRY(scePadRead, 10, 2, 30, memcpy, 0, 0, -1, 0,              \
	{{0x0080382d, 0x24030070, 0x2404001c, 0x70e31818, 0x00a42018,  \
	  0x27bd0000, 0x3c020000, 0xffb00000, 0xffbf0000, 0x24420000 },\
	{ 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,  \
	  0xffff0000, 0xff000000, 0xff000000, 0xffff0000, 0xffff0000}})\
                                                                   \
	ENTRY(scePad2Read, 10, 3, 40, memcpy, 0, 0, -1, 0,             \
	{{0x27bdffc0, 0x24020330, 0xffb10010, 0x3c03003d, 0x0080882d,  \
	  0xffb20020, 0x02222018, 0x2466ff40, 0xffbf0030, 0x00a0902d },\
	{ 0xffff0000, 0xffff0000, 0xffff0000, 0xffff0000, 0xff000000,  \
	  0xffff0000, 0xff000000, 0xffff0000, 0xff000000, 0xff000000}})\
	                                                               \
	ENTRY(main, 1, 1, 100, 0, 0, 0, -1, 0, {{ 0x0 },{ 0x0 }})      \
	                                                               \
	ENTRY(entrypoint, 1, 0, 0, 0, 0, 0, -1, 0, {{ 0x0 },{ 0x0 }})

#endif

