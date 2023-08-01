#include <stdio.h>
#include <stdlib.h>
#include "elf.h"

#define SHIFT(N) (1 << N)

enum FLG
{
    CRUDE = SHIFT(2),
    NO_CRC = SHIFT(3),
    PS2RD_ALA = SHIFT(4),
    DETAIL_REPORT = SHIFT(5),
    ONLY_SUITABLE_MASTERCODE = SHIFT(6),
    COMMENT_MASTERCODE = SHIFT(7),
};

int CTX = 0x0;

void help(void)
{
    printf("FreeMastercodeFinder by El_isra\n\tbased on PS2Rd by Aaron Clovsky <pelvicthrustman@gmail.com>\n"
           "compilation " __DATE__ " - " __TIME__ "\n"
          );
    printf("usage:\n"
           "FreeMastercodeFinder <PS2 ELF path> extra_flags...\n\n"
           "available flags: (text inside parenthesis is abbreviated flag)\n"
           " --crude  (-q)                   : Only print the mastercodes, without the function names, CRC or anything else\n"
           " --no-crc (-n)                   : Dont print ELF CRC\n"
           " --ps2rd-style (-p)              : Print results in a sintax ready to be pasted into a Cheat file for PS2RD, CheatDevice or OPL\n"
           " --ps2rd-comment-mastercode (-c) : only works with '--ps2rd-style' or '--only-suitable-mastercode'. the mastercode will have a leading comment with the corresponding function name\n"
           " --only-suitable-mastercode (-s) : instead of printing all mastercodes, only display the 'sceSifSendCmd' Mastercode, if not found, first found Mastercode is chosen instead...\n"
           " --detailed-report (-d)          : print the detailed report written by the PS2RD ELF analyzer algo\n"
          );
}

int main(int argc, char** argv)
{
    if (argc > 1)
    {
        int i, P, X = 0;
        if (argc > 2)
        {
            for (i=2; i<argc; i++)
            {
                if (!strcasecmp("--crude", argv[i]) || !strcasecmp("-q", argv[i]))
                    CTX |= (CRUDE | NO_CRC);
                if (!strcasecmp("--no-crc", argv[i]) || !strcasecmp("-n", argv[i]))
                    CTX |= NO_CRC;
                if (!strcasecmp("--ps2rd-style", argv[i]) || !strcasecmp("-p", argv[i]))
                    CTX |= PS2RD_ALA;
                if (!strcasecmp("--only-suitable-mastercode", argv[i]) || !strcasecmp("-s", argv[i]))
                    CTX |= ONLY_SUITABLE_MASTERCODE;
                if (!strcasecmp("--ps2rd-comment-mastercode", argv[i]) || !strcasecmp("-c", argv[i]))
                    CTX |= COMMENT_MASTERCODE;
                if (!strcasecmp("--detailed-report", argv[i]) || !strcasecmp("-d", argv[i]))
                    CTX |= DETAIL_REPORT;
                if (!strcasecmp("--help", argv[i]) || !strcasecmp("-h", argv[i]))
                {
                    help();
                    return 1;
                }
            }
        }
        report_t* REP = elf_analyze(argv[1]);

        if (!REP)
        {
            fprintf(stderr, "### ERROR: report is NULL\n");
            return 1;
        }
        if (REP->results < 1)
        {
            fprintf(stderr, "### ERROR: no results found (%d)\n", REP->results);
            return 1;
        } //else printf("found %d\n", REP->results);
        if (!(CTX & NO_CRC))
        {
            if (CTX & PS2RD_ALA) printf("//");
            printf("ELF CRC=%08X\n", REP->crc);
        }
        if (CTX & PS2RD_ALA) printf("\nMastercode\n");
        for (i = 0, P = -1; i < REP->results; i++)
        {
            if (REP->results_list[i].target_address)
            {
                X++;
                if (CTX & ONLY_SUITABLE_MASTERCODE) // dont print
                    ;
                else if (CTX & PS2RD_ALA)
                {
                    printf("9%07X %08X",
                           REP->results_list[i].target_address,
                           REP->results_list[i].target_data
                          );
                    if (CTX & COMMENT_MASTERCODE) printf(" //%s\n", REP->results_list[i].type);
                    else printf("\n");
                }
                else if (CTX & CRUDE)
                {
                    printf("9%07X %08X\n",
                           REP->results_list[i].target_address,
                           REP->results_list[i].target_data);
                }
                else
                {
                    printf("%-*s: 9%07X %08X\n",
                           16, REP->results_list[i].type,
                           REP->results_list[i].target_address,
                           REP->results_list[i].target_data);
                }
                if (!strcasecmp("sceSifSendCmd", REP->results_list[i].type))
                {
                    P = i;
                }
            }
        }
        if (X == 0)
        {
            fprintf(stderr, "Could not find any mastercode\n");
            return 1;
        }
        if (P == -1) P = 0; // no sceSifSendCmd found, fall back to the last mastercode found...
        if (CTX & ONLY_SUITABLE_MASTERCODE)
        {
            printf("9%07X %08X", REP->results_list[P].target_address, REP->results_list[P].target_data);
            if (CTX & COMMENT_MASTERCODE) printf(" //%s\n", REP->results_list[P].type);
            else printf("\n");
        }
        if (CTX & DETAIL_REPORT) puts("\n\n"), puts(REP->extended_report);
        elf_free_report(REP);
    }
    else
    {
        help();
        return 1;
    }
    return 0;
}
