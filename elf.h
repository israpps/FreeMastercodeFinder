/**
 * ELF Analysis Library
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
 * link from where source code was taken: https://web.archive.org/web/20150908081500/http://psx-scene.com/forums/attachments/f19/42079d1363317065-ps2rdmod-ps2rd-w-pnach-support-ps2rdmod_100_source.zip
 */



#ifndef ELF_H_INCLUDED
#define ELF_H_INCLUDED

#include "ps2types.h"
//--------------ELF File Format----------------
typedef struct
{
	u32 e_ident[4];
	u16 e_type;
	u16 e_machine;
	u32 e_version;
	u32 e_entry;	//the virtual address to which the system first transfers control
	u32 e_phoff;	//offset of Program Header Table
	u32 e_shoff;	//offset of Section Header Table
	u32 e_flags;	//EF_machine_flag
	u16 e_ehsize;	//ELF header size in bytes
	u16 e_phentsize;//program header table size in bytes
	u16 e_phnum;	//the number of entries in the program header table.
	u16 e_shentsize;//a section header's size in bytes
	u16 e_shnum;	//the number of entries in the section header table
	u16 e_shstrndx;	//the section header table index of the entry associated with the section name string table
} elf_header;

typedef struct
{
	u32 sh_name;		// section name
	u32 sh_type;		// SHT_...
	u32 sh_flags;		// SHF_...
	u32 sh_addr;		// virtual address
	u32 sh_offset;		// file offset
	u32 sh_size;		// section size
	u32 sh_link;		// misc info
	u32 sh_info;		// misc info
	u32 sh_addralign;	// memory alignment
	u32 sh_entsize;		// entry size if table
} elf_section_header;

typedef struct
{
	u32 p_type;		//Segment type
	u32 p_offset;	//Segment file offset
	u32 p_vaddr;	//Segment virtual address
	u32 p_paddr;	//Segment physical address
	u32 p_filesz;	//Segment size in file
	u32 p_memsz;	//Segment size in memory
	u32 p_flags;	//Segment flags
	u32 p_align;	//Segment alignment
} elf_segment_header;

typedef struct
{
	u32 st_name;	//Symbol name index in symbol string table
	u32 st_value;	//Varies, Address for FUNC
	u32 st_size;	//Length of function?
	u8  st_info;	//((st_info) & 0xf) == 2 //Function type
	u8  st_other;	//No defined meaning
	u16 st_shndx;	//Relative section index
} elf_symbol;

//-------------ELF Analysis Struct-------------

typedef struct
{
	u8         *elf;        			//ELF file in memory
	u32         size;       			//ELF file size
	u32         entrypoint; 			//Virtual address of entrypoint

	u32         executable_segments;	//Number of executable segments
	u32        *virtual_offset;			//Virtual offset for Physical->Virtual Address conversion within executable segments
	u32        *executable_offset;		//Physical offset of executable segments
	u32        *executable_length;		//Length of executable segments


	elf_symbol *symtab;					//Pointer to symtab (NULL => nonexistant)
	u32         symtab_length;			//Length of symtab (units of sizeof(elf_symbol_table))
	char       *strtab;					//Pointer to strtab (NULL => nonexistant)

} elf_t;

//-------------Function ID Struct--------------

typedef struct
{
	//Primary function identification criteria
	char *name;		//Name of function - Used to locate function in symbol table if present

	u32  *pattern;	//Pointer to initial instructions in function
	u32  *mask;		//Pointer to mask for initial instructions in function (variable instructions)
	u32   length;	//Number of instructions in initial instructions (32 bits per instruction)

	//Confirmational function identification criteria
	u32   jal_count;						//If nonzero - The jal_count occurence of the JAL instruction in the function
											//will be evaluated to determine if the function has been correctly identified
											//If zero the function will be identified only by initial instructions
	u32   jal_scope;						//Upper bound of estimated function length (units of 32-bit instructions)
	u32  *jal_address;						//JAL target address - The address specified by the JAL must match this address to confirm function identity
											//(if 0 is specified jal_relative_offset and jal_relative_offset_tolerance will be used)
	s32   jal_relative_offset;				//JAL relative offset (units of 32-bit instructions) - The address specified by the JAL must be
											//jal_relative_offset bytes (+/- jal_relative_offset_tolerance) from the JAL instruction's address
											//If zero and jal_address specifies zero thentarget will be identified as JAL without confirmation
	u32   jal_relative_offset_tolerance;	//Tolerance for JAL relative address (units of 32-bit instructions)

	//Target instruction (mastercode) identification criteria
	s32   target_offset;		//Offset from function start of target instruction (units of 32-bit instructions)
								//When this is non-negative it is used regardless of target_jal_offset (negative values are ignored)
								//If jal_count is zero and target_offset is negative no instruction will be identified
								//(this is useful for functions which are only required to be identified for comparison to jal_address)
	s32   target_jal_offset;	//Offset from JAL instruction of target instruction (units of 32-bit instructions)
								//Note: jal_count must be specified and target_offset must be negative

	//Working values
	u32   counter;				//Initial instructions comparison counter
	u32   jal_counter;			//JAL occurence counter

	//Values derived from analysis
	u32   address;				//Address of function (if multiple ???)
	u32   target_address;		//Address of identified target within function (zero when no instruction is identified)
	s32   candidates;			//Number of binary-only matches (initial instructions criteria only)
								//This number is set to -1 when a symbol table identification occurs (no ambiguity)
	s32   matches;				//Number of confirmed matches (nonzero indicates id criteria ambiguity)
} elf_function_id;

//--------------ELF Report Struct--------------

typedef struct
{
	//Result type (function name)
	char *type;
	//Function candidates
	s32   candidates;
	//Function matches
	u32   matches;
	//Target determined
	u32   target_address;
	u32   target_data;
	//Executable segment
	u32   segment;
} result_t;

typedef struct
{
	u32               results;
	result_t         *results_list;
	u32               crc;
	char             *extended_report;
	elf_t            *elf;
	elf_function_id **elf_function_list;
} report_t;

elf_t *elf_read(char *elf_file);
report_t *elf_analyze(char *elf_file);

#ifndef PS2RD_VERSION
void elf_free_report(report_t *report);
#endif

#endif // ELF_H_INCLUDED
