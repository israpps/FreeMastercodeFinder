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

#ifndef ELF_MODULE
#define ELF_MODULE


#include <stdio.h>
#include <string.h>

#ifndef PS2RD_VERSION
	#include <malloc.h>

	#if !defined(_MSC_VER) || (defined(_MSC_VER) && !defined(_MT))
//		#define malloc(x)     HeapAlloc  (GetProcessHeap(), 0, x)
//		#define realloc(x, y) HeapReAlloc(GetProcessHeap(), 0, x, y)
//		#define free(x)	      HeapFree   (GetProcessHeap(), 0, x)
	#endif
#include "ps2types.h"
#else
	#include <fileio.h>
	#include "mycdvd.h"

	#define ELF_FILE_ADDRESS 0x00800000
	#define ELF_VOFF_ADDRESS 0x007a0000
	#define ELF_EOFF_ADDRESS 0x007b0000
	#define ELF_ELEN_ADDRESS 0x007c0000
	#define ELF_FLST_ADDRESS 0x007d0000
	#define ELF_RLST_ADDRESS 0x007e0000
	#define ELF_EREP_ADDRESS 0x007f0000
#endif

#ifdef ELF_DEBUG
	#define ELF_DEBUG_EXTENDED_REPORT_SIZE 4096

	#ifdef _MSC_VER
		#define snprintf(buffer, size, ...) (_snprintf(buffer, size, __VA_ARGS__), *(buffer + size - 1) = '\0')
	#endif

	#define snconcatf(buffer, size, ...) (buffer ? snprintf(&buffer[strlen(buffer)], size - strlen(buffer), __VA_ARGS__) : 0)
#endif

#include "elf.h"
//-----------Function ID Init Macro------------

//#define ENTRY(function_name, length, jal_count, jal_scope, j_type, jal_address, jal_relative_offset, jal_relative_offset_tolerance, target_offset, target_jal_offset, pattern, mask);

#include "elf_definitions.h"

#define PASTE(x, y)  x ## y
#define EVAL(x, y)   PASTE(x,y)
#define CONCAT(x, y) EVAL(x,y)

#define CONVENTION(function_name) elf_function_ ## function_name

#define DECLARE_ELF_FUNCTION_ID(function_name, length, jc, js, ja, jro, jrot, to, tjo, ...)                          \
	u32 CONCAT(CONVENTION(function_name),_data[2][length]) = __VA_ARGS__;                                            \
	elf_function_id CONVENTION(function_name) = { #function_name, (u32 *) CONCAT(CONVENTION(function_name),_data[0]),\
												  (u32 *) CONCAT(CONVENTION(function_name),_data[1]),                \
												  length, jc, js, &(CONVENTION(ja).address),                         \
												  jro, jrot, to, tjo, 0, 0, 0, 0, 0, 0 };

//Initialize function identifiers
FOREACH_ELF_FUNCTION_ID(DECLARE_ELF_FUNCTION_ID);

//Read ELF
elf_t *elf_read(char *elf_file)
{
	u32                 i, k;
	elf_header         *header;
	elf_segment_header *segment;
	elf_section_header *section;
	static elf_t        result;

	#ifndef PS2RD_VERSION
		FILE *input;
	#else
		int     fd;
		char    elfname[FIO_PATH_MAX];
		enum    dev_id dev = DEV_CD;
	#endif

	#ifndef PS2RD_VERSION
		/*********Open File*********/
		input = fopen(elf_file, "rb");

		if (!input)
		{
			fprintf(stderr, "Cant open input file (%s)\n", elf_file);
			return NULL;
		}

		/******Allocate Buffer******/
		fseek(input, 0, SEEK_END);
		result.size = ftell(input);

		result.elf = (u8 *)malloc(result.size);

		if (!result.elf)
		{
			fprintf(stderr, "failed to allocate 0x%x bytes\n", result.size);
			fclose(input);
			return NULL;
		}

		fseek(input, 0, SEEK_SET);

		/*********Read File*********/
		if (fread(result.elf, result.size, 1, input) != 1)
		{
			fprintf(stderr, "Failed to read file\n");
			fclose(input);
			free(result.elf);
			return NULL;
		}

		fclose(input);
	#else
		result.elf = (u8 *)ELF_FILE_ADDRESS;

		/*********Open File*********/
		if (elf_file == NULL || (elf_file != NULL && (dev = get_dev(elf_file)) == DEV_CD))
		{
			_cdStandby(CDVD_NOBLOCK);
			delay(100);
		}

		if (elf_file == NULL)
		{
			if (cdGetElf(elfname) < 0)
			{
				_cdStop(CDVD_NOBLOCK);
				return NULL;
			}

			elf_file = elfname;
		}

		fd = open(elf_file, O_RDONLY);

		if (fd < 0)
		{
			return NULL;
		}

		result.size = lseek(fd, 0, SEEK_END);

		if (result.size == -1)
		{
			close(fd);
			return NULL;
		}

		/*********Read File*********/
		if (lseek(fd, 0, SEEK_SET) == -1)
		{
			close(fd);
			return NULL;
		}

		if (read(fd, (void *)result.elf, result.size) != result.size)
		{
			close(fd);
			return NULL;
		}

		close(fd);
	#endif

	/**********Analyze**********/

	//Verify ELF magic
	if (result.elf[0] != 0x7f || result.elf[1] != 0x45 || result.elf[2] != 0x4C || result.elf[3] != 0x46)
	{
		#ifndef PS2RD_VERSION
			free(result.elf);
		#endif
		return NULL;
	}

	//Locate headers
	header  = (elf_header *)result.elf;
	segment = (elf_segment_header *)&result.elf[header->e_phoff];
	section = (elf_section_header *)&result.elf[header->e_shoff];

	result.entrypoint = header->e_entry;

	//Count number of executable segments
	for (i = 0, k = 0; i < (u32)header->e_phnum; i++)
	{
		if (segment[i].p_type == 1 && (segment[i].p_flags & 1))//LOAD & EXECUTABLE
		{
			k++;
		}
	}

	//Allocate executable segment information lists
	result.executable_segments = k;

	#ifndef PS2RD_VERSION
		result.virtual_offset = (u32 *)malloc(result.executable_segments * sizeof(u32));

		if (!result.virtual_offset)
		{
			free(result.elf);
			return NULL;
		}

		result.executable_offset = (u32 *)malloc(result.executable_segments * sizeof(u32));

		if (!result.executable_offset)
		{
			free(result.elf);
			free(result.virtual_offset);
			return NULL;
		}

		result.executable_length = (u32 *)malloc(result.executable_segments * sizeof(u32));

		if (!result.executable_length)
		{
			free(result.elf);
			free(result.virtual_offset);
			free(result.executable_offset);
			return NULL;
		}
	#else
		result.virtual_offset    = (u32 *)ELF_VOFF_ADDRESS;
		result.executable_offset = (u32 *)ELF_EOFF_ADDRESS;
		result.executable_length = (u32 *)ELF_ELEN_ADDRESS;
	#endif

	//Calculate executable offsets
	for (i = 0, k = 0; i < (u32)header->e_phnum; i++)
	{
		if (segment[i].p_type == 1 && (segment[i].p_flags & 1))//LOAD & EXECUTABLE
		{
			result.virtual_offset[k]    = segment[i].p_vaddr - segment[i].p_offset;
			result.executable_offset[k] = segment[i].p_offset;
			result.executable_length[k] = segment[i].p_filesz;

			k++;
		}
	}

	//Find symbol table and string table offsets (if they exist)
	result.symtab = NULL;
	result.symtab_length = 0;
	result.strtab = NULL;

	if (header->e_shstrndx != 0xFFFF)
	{
		for (i = 0; i < (u32)header->e_shnum; i++)
		{
			if (!strncmp(".symtab", &result.elf[section[header->e_shstrndx].sh_offset + section[i].sh_name], strlen(".symtab")))
			{
				result.symtab        = (elf_symbol *)&result.elf[section[i].sh_offset];
				result.symtab_length = section[i].sh_size / sizeof(elf_symbol);
			}
			else if (!strncmp(".strtab", &result.elf[section[header->e_shstrndx].sh_offset + section[i].sh_name], strlen(".strtab")))
			{
				result.strtab = (char *)&result.elf[section[i].sh_offset];
			}
		}
	}

	return &result;
}

//Analyze ELF
report_t *elf_analyze(char *elf_file)
{
	u32               t, i, k, j, address, elf_function_list_length, *data;
	s32               difference;
	elf_t            *elf;
	elf_function_id **elf_function_list;
	static report_t   report;

	elf = elf_read(elf_file);

	if (!elf) return NULL;

	data = (u32 *)elf->elf;

	//----Create array of function identifiers----

	//Allocate array
	i = 0;

	#define COUNT_ELF_FUNCTION_ID(function_name, length, jc, js, ja, jro, jrot, to, tjo, ...)\
		i++;
	FOREACH_ELF_FUNCTION_ID(COUNT_ELF_FUNCTION_ID);

	elf_function_list_length = i;

	#ifndef PS2RD_VERSION
		elf_function_list = (elf_function_id **)malloc(elf_function_list_length * sizeof(elf_function_id *));
	#else
		elf_function_list = (elf_function_id **)ELF_FLST_ADDRESS;
	#endif

	if (!elf_function_list)
	{
		#ifndef PS2RD_VERSION
			free(elf->elf);
			free(elf->virtual_offset);
			free(elf->executable_offset);
			free(elf->executable_length);
		#endif
		return NULL;
	}

	//Populate array
	i = 0;

	#define COPY_ELF_FUNCTION_ID(function_name, length, jc, js, ja, jro, jrot, to, tjo, ...)\
		elf_function_list[i++] = &CONVENTION(function_name);
	FOREACH_ELF_FUNCTION_ID(COPY_ELF_FUNCTION_ID);

	//Required to allow multiple calls to elf_analyze() (not used on console)
	for (i = 0; i < elf_function_list_length; i++)
	{
		elf_function_list[i]->counter = 0;
		elf_function_list[i]->jal_counter = 0;
		elf_function_list[i]->address = 0;
		elf_function_list[i]->target_address = 0;
		elf_function_list[i]->candidates = 0;
		elf_function_list[i]->matches = 0;
	}

	//Alocate & Initialize report
	memset(&report, 0, sizeof(report));

	report.results = elf_function_list_length - 1;

	#ifndef PS2RD_VERSION
		report.results_list = (result_t *)malloc(report.results * sizeof(result_t));
	#else
		report.results_list = (result_t *)ELF_RLST_ADDRESS;
	#endif

	if (!report.results_list)
	{
		#ifndef PS2RD_VERSION
			free(elf->elf);
			free(elf->virtual_offset);
			free(elf->executable_offset);
			free(elf->executable_length);
			free(elf_function_list);
		#endif
		return NULL;
	}

	memset(report.results_list, 0, report.results * sizeof(result_t));

	#ifdef ELF_DEBUG
		#ifndef PS2RD_VERSION
			report.extended_report = (char *)malloc(ELF_DEBUG_EXTENDED_REPORT_SIZE);
		#else
			report.extended_report = (char *)ELF_EREP_ADDRESS;
		#endif

		if (report.extended_report) *report.extended_report = '\0';
	#else
		report.extended_report = NULL;
	#endif

	//----Find labeled functions and calculate ELF CRC----

	#ifdef ELF_DEBUG
		snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, ">Beginning Analysis\n");
	#endif

	if (elf->symtab && elf->strtab)
	{
		#ifdef ELF_DEBUG
			snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, ">Processing ELF symbol table...\n");
		#endif

		for (i = 0; i < elf->symtab_length; i++)
		{
			if ((elf->symtab[i].st_info & 0xf) == 2) //Function-type symbol
			{
				for (k = 1; k < elf_function_list_length; k++)
				{
					if (!elf_function_list[k]->address)
					{
						if (!strcmp(elf_function_list[k]->name, &elf->strtab[elf->symtab[i].st_name]))
						{
							elf_function_list[k]->address = elf->symtab[i].st_value;
							elf_function_list[k]->matches = 1;
							elf_function_list[k]->candidates = -1; //Function has been located unambiguously

							//Locate target if possible
							if (elf_function_list[k]->target_offset >= 0)
							{
								elf_function_list[k]->target_address = elf_function_list[k]->address + (elf_function_list[k]->target_offset << 2);
							}
							//Set JAL scope to actual function length
							else if (elf_function_list[k]->jal_count)
							{
								elf_function_list[k]->jal_scope = elf->symtab[i].st_size >> 2;
							}

							#ifdef ELF_DEBUG
								snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\t%s() found @ %08X (label)\n", elf_function_list[k]->name, elf_function_list[k]->address);
							#endif
						}
					}
				}
			}
		}
	}
	#ifdef ELF_DEBUG
		else
		{
			snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, ">ELF symbol table not found\n");
		}
	#endif

	//----Find unlabeled functions and calculate ELF CRC----

	//Entrpoint and main are processed specially
	for (k = 0; k < elf_function_list_length; k++)
	{
		if (!strcmp(elf_function_list[k]->name, "entrypoint"))
		{
			elf_function_list[k]->address = elf->entrypoint;
			elf_function_list[k]->candidates = -3;
		}
		else if (!strcmp(elf_function_list[k]->name, "main"))
		{
			if (elf_function_list[k]->candidates == 0)
			{
				elf_function_list[k]->candidates = -4;
			}
		}
	}

	#ifdef ELF_DEBUG
		snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, ">Processing non-executable range 0x%08X-0x%08X...\n", 0, elf->executable_offset[0]);
	#endif

	//Calculate CRC for non-executable ELF segment
	for (i = 0; i < (elf->executable_offset[0] >> 2); i++, data++) report.crc ^= *data;

	for (t = 0; t < elf->executable_segments; t++)
	{
		#ifdef ELF_DEBUG
			snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, ">Processing executable range 0x%08X-0x%08X...\n", i << 2, elf->executable_offset[t] + elf->executable_length[t]);
		#endif

		//Analyze executable ELF segment
		for (; i < ((elf->executable_offset[t] >> 2) + (elf->executable_length[t] >> 2)); i++, data++)
		{
			//Calculate CRC for executable ELF segment
			report.crc ^= *data;

			//Analyze
			for (k = 1; k < elf_function_list_length; k++)
			{
				if (elf_function_list[k]->candidates >= 0)
				{
					if (elf_function_list[k]->counter < elf_function_list[k]->length)
					{
						if ((*data & elf_function_list[k]->mask[elf_function_list[k]->counter]) == (elf_function_list[k]->pattern[elf_function_list[k]->counter] & elf_function_list[k]->mask[elf_function_list[k]->counter]) && elf_function_list[k]->length != 1)
						{
							elf_function_list[k]->counter++;
						}
						else
						{
							elf_function_list[k]->counter = 0;
						}
					}
					else if (elf_function_list[k]->counter < elf_function_list[k]->jal_scope)
					{
						//End of function/return statement (JR $RA) -> Stop looking
						if (*data == 0x03e00008)
						{
							elf_function_list[k]->counter = 0;
							elf_function_list[k]->jal_counter = 0;
						}
						else
						{
							elf_function_list[k]->counter++;

							if ((*data & 0xfc000000) == 0x0c000000) //JAL instruction
							{
								elf_function_list[k]->jal_counter++;

								if (elf_function_list[k]->jal_counter == elf_function_list[k]->jal_count)
								{
									if (elf_function_list[k]->jal_address == &elf_function_list[0]->address)
									{
										if (elf_function_list[k]->jal_relative_offset)
										{
											difference = (((s32)*data & ~0xfc000000) << 2) - ((u32)data - (u32)elf->elf + (u32)elf->virtual_offset[t]) - (s32)(elf_function_list[k]->jal_relative_offset << 2);
											difference = (difference < 0 ? -difference : difference) >> 2;

											if ((u32)difference <= elf_function_list[k]->jal_relative_offset_tolerance)
											{
												elf_function_list[k]->address = (u32)data - (u32)elf->elf + (u32)elf->virtual_offset[t] - ((elf_function_list[k]->counter - 1) << 2);
												elf_function_list[k]->target_address = (u32)data - (u32)elf->elf + (u32)elf->virtual_offset[t] + (elf_function_list[k]->target_jal_offset << 2);
												report.results_list[k - 1].segment = t;
												elf_function_list[k]->matches++;

												#ifdef ELF_DEBUG
													snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\t%s() found @ %08X\n", elf_function_list[k]->name, elf_function_list[k]->address);
												#endif
											}
										}
										else //Do not verify JAL target
										{
											elf_function_list[k]->address = (u32)data - (u32)elf->elf + (u32)elf->virtual_offset[t] - ((elf_function_list[k]->counter - 1) << 2);
											elf_function_list[k]->target_address = (u32)data - (u32)elf->elf + (u32)elf->virtual_offset[t] + (elf_function_list[k]->target_jal_offset << 2);
											report.results_list[k - 1].segment = t;
											elf_function_list[k]->matches++;

											#ifdef ELF_DEBUG
												snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\t%s() found @ %08X\n", elf_function_list[k]->name, elf_function_list[k]->address);
											#endif
										}
									}
									else
									{
										elf_function_list[k]->address = ((u32)data - (u32)elf->elf + (u32)elf->virtual_offset[t] - ((elf_function_list[k]->counter - 1) << 2));
										//This will be verified later (target_jal_offset will be added if verified)
										elf_function_list[k]->target_address = (u32)data - (u32)elf->elf + (u32)elf->virtual_offset[t];
										report.results_list[k - 1].segment = t;
										elf_function_list[k]->matches++;
									}

									elf_function_list[k]->counter = 0;
									elf_function_list[k]->jal_counter = 0;
								}
							}
						}

					}
					else
					{
						elf_function_list[k]->counter = 0;
						elf_function_list[k]->jal_counter = 0;
					}

					//Initial instruction comparison succeeded -> declare candidate
					if (elf_function_list[k]->counter == elf_function_list[k]->length)
					{
						elf_function_list[k]->candidates++;

						#ifdef ELF_DEBUG
							if (elf_function_list[k]->jal_count)
							{
								snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\t%s() candidate found @ %08X\n", elf_function_list[k]->name, (u32)data - (u32)elf->elf + (u32)elf->virtual_offset[t] - ((elf_function_list[k]->counter - 1) << 2));
							}
						#endif

						//Declare found if function requires only initial instruction comparison
						if (!elf_function_list[k]->jal_count)
						{
							elf_function_list[k]->address = (u32)data - (u32)elf->elf + (u32)elf->virtual_offset[t] - ((elf_function_list[k]->counter - 1) << 2);
							elf_function_list[k]->matches++;

							//Locate target if required
							if (elf_function_list[k]->target_offset >= 0)
							{
								elf_function_list[k]->target_address = elf_function_list[k]->address + (elf_function_list[k]->target_offset << 2);
								report.results_list[k - 1].segment = t;
							}

							elf_function_list[k]->counter = 0;

							#ifdef ELF_DEBUG
								snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\t%s() found @ %08X\n", elf_function_list[k]->name, elf_function_list[k]->address);
							#endif
						}
					}
				}
				else if (elf_function_list[k]->candidates >= -2)
				{
					address = (u32)data - (u32)elf->elf + (u32)elf->virtual_offset[t];

					if (address >= (elf_function_list[k]->address + (elf_function_list[k]->length << 2)))
					{
						if (address < elf_function_list[k]->address + (elf_function_list[k]->length << 2) + (elf_function_list[k]->jal_scope << 2))
						{
							report.results_list[k - 1].segment = t;

							if (elf_function_list[k]->target_offset < 0 && elf_function_list[k]->jal_count != 0)
							{
								if (*data == 0x03e00008)
								{
									elf_function_list[k]->counter = 1;
									elf_function_list[k]->jal_counter = 0;
								}
								else if ((*data & 0xfc000000) == 0x0c000000 && !elf_function_list[k]->counter) //JAL instruction
								{
									elf_function_list[k]->jal_counter++;

									if (elf_function_list[k]->jal_counter == elf_function_list[k]->jal_count)
									{
										if (elf_function_list[k]->jal_address == &elf_function_list[0]->address)
										{
											if (elf_function_list[k]->jal_relative_offset)
											{
												difference = (((s32)*data & ~0xfc000000) << 2) - address - (s32)(elf_function_list[k]->jal_relative_offset << 2);
												difference = (difference < 0 ? -difference : difference) >> 2;

												if ((u32)difference <= elf_function_list[k]->jal_relative_offset_tolerance)
												{
													elf_function_list[k]->target_address = address + (elf_function_list[k]->target_jal_offset << 2);


													#ifdef ELF_DEBUG
														snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\t%s() confirmed @ %08X\n", elf_function_list[k]->name, elf_function_list[k]->address);
													#endif
												}
											}
											else //Do not verify JAL target
											{
												elf_function_list[k]->target_address = address + (elf_function_list[k]->target_jal_offset << 2);
												report.results_list[k - 1].segment = t;

												#ifdef ELF_DEBUG
													snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\t%s() confirmed @ %08X\n", elf_function_list[k]->name, elf_function_list[k]->address);
												#endif
											}
										}
										else
										{
											//This will be verified later (target_jal_offset will be added if verified)
											elf_function_list[k]->target_address = address;
											report.results_list[k - 1].segment = t;
										}
									}
								}
							}
						}
					}
				}
				else if (elf_function_list[k]->candidates == -3)
				{
					if (!elf_function_list[k]->counter)
					{
						report.results_list[k - 1].segment = t;
						address = (u32)data - (u32)elf->elf + (u32)elf->virtual_offset[t];

						if (address >= elf_function_list[k]->address)
						{
							if ((*data & 0xfc000000) == 0x0c000000) //JAL instruction
							{
								elf_function_list[k]->jal_counter++;
							}

							if (elf_function_list[k]->jal_counter == 3)
							{
								//elf_function_list[k]->target_address = address;
								//report.results_list[k - 1].segment = t;

								elf_function_list[k]->counter = 1;

								//Identify the address of main if it is unlabeled
								for (j = 1; j < elf_function_list_length; j++)
								{
									if (!strcmp(elf_function_list[j]->name, "main")) break;
								}

								if (j != elf_function_list_length)
								{
									if (elf_function_list[j]->candidates != -1 && address < ((*data & ~0xfc000000) << 2))
									{
										elf_function_list[j]->address = (*data & ~0xfc000000) << 2;
										elf_function_list[j]->candidates = -2;

										#ifdef ELF_DEBUG
											snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\t%s() referenced @ %08X\n", elf_function_list[j]->name, elf_function_list[j]->address);
										#endif
									}
								}
							}
							//J (which do not jump backwards after entrypoint), JR and JALR instructions end entrypoint code
							else if (((*data & 0xfc000000) == 0x08000000 && !(((*data & ~0xfc000000) << 2) < address && ((*data & ~0xfc000000) << 2) >= elf_function_list[k]->address)) || ((*data & 0xfc000000) == 0x00000000 && ((*data & 0x0000003f) == 0x00000009 || (*data & 0x0000003f) == 0x00000008)))
							{
								//elf_function_list[k]->target_address = address;
								//report.results_list[k - 1].segment = t;
								elf_function_list[k]->counter = 1;
							}
						}
					}
				}
			}
		}

		//Calculate CRC for non-executable ELF segment
		if ((t + 1) != elf->executable_segments)
		{
			#ifdef ELF_DEBUG
				snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, ">Processing non-executable range 0x%08X-0x%08X...\n", i << 2, elf->executable_offset[t + 1]);
			#endif

			for (; i < (elf->executable_offset[t + 1] >> 2); i++, data++) report.crc ^= *data;
		}
		else
		{
			#ifdef ELF_DEBUG
				snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, ">Processing non-executable range 0x%08X-0x%08X...\n", i << 2, elf->size);
			#endif

			for (; i < (elf->size >> 2); i++, data++) report.crc ^= *data;
		}
	}

	#ifdef ELF_DEBUG
		snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\t>Confirming JAL function references...\n");
	#endif

	//Verify address-referencing JALs
	for (k = 1; k < elf_function_list_length; k++)
	{
		//If JAL address confirmed function was found - verify address
		if (elf_function_list[k]->address && elf_function_list[k]->target_address && elf_function_list[k]->jal_count && elf_function_list[k]->jal_address != &elf_function_list[0]->address)
		{
			if (((*(u32*)(elf_function_list[k]->target_address + (u32)elf->elf - (u32)elf->virtual_offset[report.results_list[k - 1].segment]) & ~0xfc000000) << 2) == *elf_function_list[k]->jal_address)
			{
				#ifdef ELF_DEBUG
					if (elf_function_list[k]->candidates == -1)
					{
						snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\t%s() confirmed @ %08X\n", elf_function_list[k]->name, elf_function_list[k]->address);
					}
					else
					{
						snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\t%s() found @ %08X\n", elf_function_list[k]->name, elf_function_list[k]->address);
					}
				#endif

				elf_function_list[k]->target_address += (elf_function_list[k]->target_jal_offset << 2);
			}
			else
			{
				elf_function_list[k]->target_address = 0;
			}
		}
	}

	#ifdef ELF_DEBUG
		snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, ">Finished processing ELF\n");
		snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, "\tELF CRC = %08X\n", report.crc);
		snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, ">Preparing report...\n");
	#endif

	for (i = 0; i < report.results; i++)
	{
		k = i + 1;
		report.results_list[i].type = elf_function_list[k]->name;
		report.results_list[i].candidates = elf_function_list[k]->candidates;
		report.results_list[i].matches = elf_function_list[k]->matches;
		report.results_list[i].target_address = elf_function_list[k]->target_address;

		if (report.results_list[i].target_address)
		{
			report.results_list[i].target_data = *(u32 *)((u32)elf->elf + elf_function_list[k]->target_address - (u32)elf->virtual_offset[report.results_list[i].segment]);
		}
	}

	#ifdef ELF_DEBUG
		snconcatf(report.extended_report, ELF_DEBUG_EXTENDED_REPORT_SIZE, ">Analysis Concluded");
	#endif

	report.elf = elf;

	return &report;
}

#ifndef PS2RD_VERSION
	void elf_free_report(report_t *report)
	{
		free(report->elf->virtual_offset);
		free(report->elf->executable_offset);
		free(report->elf->executable_length);
		free(report->elf->elf);
		free(report->results_list);
		free(report->elf_function_list);

		#ifdef ELF_DEBUG
			if (report->extended_report) free(report->extended_report);
		#endif
	}
#endif
#endif
