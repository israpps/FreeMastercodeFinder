# FreeMastercodeFinder
 An open source spiritual succesor of pelvictrustman's mastercode finder

Main purpose of making this program was to have a mastercode finder that can output mastercodes in the format that i'm using for my widescreen hacks archive

also, there seemed to be no easy to find copy of the original mastercode finder source code. the one on this program comes from PS2RD

## usage:
```
FreeMastercodeFinder <PS2 ELF path> extra_flags...
```
available flags: (text inside parenthesis is abbreviated flag)

 Flag  | Short Flag | effect
------ | ---------- | ------- |
`--crude` | `-q` | Only print the mastercodes, without the function names, CRC or anything else
`--no-crc` | `-n` | Dont print ELF CRC
`--ps2rd-style` | `-p` | Print results in a sintax ready to be pasted into a Cheat file for PS2RD, CheatDevice or OPL
`--ps2rd-comment-mastercode` | `-c` | only works with `--ps2rd-style` or `--only-suitable-mastercode`. the mastercode will have a leading comment with the corresponding function name
`--only-suitable-mastercode` | `-s` | instead of printing all mastercodes, only display the `sceSifSendCmd` Mastercode, if not found, first found Mastercode is chosen instead...
`--detailed-report` | `-d` | print the detailed report written by the PS2RD ELF analyzer algo
