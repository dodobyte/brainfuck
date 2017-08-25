/*
 * Brainfuck compiler for Windows. 
 * This program takes brainfuck source as input and compiles it to 
 * x86 machine code. Generates Win32 PE executable.
 * All Rights Free.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint8_t *code;		/* code section */
uint32_t ncode;		/* size of code section */

uint8_t *import;	/* import table */
uint32_t nimport;	/* size of import table */

/* virtual addresses of imported functions */
uint32_t imp_exit;
uint32_t imp_getchar;
uint32_t imp_putchar;

char mem[50000];	/* brainfuck program */
int stack[4096];	/* runtime stack for [ locations */

/*
 * Read program from 'mem' and compile it to 'code'.
 * This is the only relevant code for brainfuck, it converts 
 * brainfuck source into x86 machine code. Other functions are
 * PE related and should not be worried about.  
 */
void compile()
{
	int pc = 0;
	char *codp = mem;					
	int *sp    = stack;
	uint32_t data = 0x400000 + 0x1000 + nimport;

	/* mov ebp, .data */
	code[pc++] = 0xBD;
	*(uint32_t *)(code + pc) = data;
	pc += 4;

	while (*codp) {
		
		switch (*codp++) {
		case '>':
			code[pc++] = 0x45;	/* inc ebp */
			break;
		case '<':
			code[pc++] = 0x4D;	/* dec ebp */
			break;
		case '+':
			memcpy(code + pc, "\xFE\x45\x00", 3);	/* inc byte[ebp] */
			pc += 3;
			break;
		case '-':
			memcpy(code + pc, "\xFE\x4D\x00", 3);	/* dec byte[ebp] */
			pc += 3;
			break;
		case '.':
			memcpy(code + pc, "\x0F\xB6\x45\x00", 4); /* movzx eax, byte[ebp] */
			pc += 4;
			memcpy(code + pc, "\x50", 1);	/* push eax */
			pc++;
			memcpy(code + pc, "\xFF\x15", 2); /* call putchar */
			pc += 2;
			*(uint32_t *)(code + pc) = imp_putchar;
			pc += 4;
			memcpy(code + pc, "\x83\xC4\x04", 3);	/* add esp, 4 */
			pc += 3;
			break;
		case ',':
			memcpy(code + pc, "\xFF\x15", 2); /* call getchar */
			pc += 2;
			*(uint32_t *)(code + pc) = imp_getchar;
			pc += 4;
			memcpy(code + pc, "\x88\x45\x00", 3);	/* mov byte[ebp], al */
			pc += 3;
			break;
		case '[':
			*sp++ = pc;
			memcpy(code + pc, "\x0F\xB6\x45\x00", 4); /* movzx eax, byte[ebp]*/
			pc += 4;
			memcpy(code + pc, "\x85\xC0", 2);	/* test eax, eax */
			pc += 2;
			memcpy(code + pc, "\x0F\x84\x00\x00\x00\x00", 6); /* jz endwhile */
			pc += 6;
			break;
		case ']':
			{
				int bpc = *--sp;
				*(uint32_t *)(code + bpc + 8) = pc - bpc - 7;
			
				code[pc] = 0xE9; /* jmp 'location of [ code' */
				*(uint32_t *)(code + pc + 1) = (uint32_t)(bpc - pc - 5);
				pc += 5;
			}
			break;
		}
	}

	memcpy(code + pc, "\x6A\x00", 2);	/* push 0 */
	pc += 2;
	memcpy(code + pc, "\xFF\x15", 2);	/* call exit */
	pc += 2;
	*(uint32_t *)(code + pc) = imp_exit;
	pc += 4;

	ncode = pc;
}

/*
 * Since the necessary functions are predefined, we can construct
 * import table before compiling program.
 * Import table resides at the beginning of first section,
 * so addresses are static and don't depend on code sections size.
 */
void create_imports()
{
	/* 
	 * import desc. = 20 bytes. end marker = 20 bytes.
	 * thunk array = 16 bytes (3 imports + end marker)
	 * no org. first thunk. we can't be bound, big deal!
	 */
	memcpy(import + 56, "msvcrt.dll\0", 11);
	memcpy(import + 67, "\0\0exit\0", 7);
	memcpy(import + 74, "\0\0getchar\0", 10);
	memcpy(import + 84, "\0\0putchar\0", 10);
	nimport = 94;

	/* name rva */
	*(uint32_t *)(import + 12) = 0x1000 + 56;
	/* first thunk */
	*(uint32_t *)(import + 16) = 0x1000 + 40;
	/* thunk array */
	*(uint32_t *)(import + 40) = 0x1000 + 67;
	*(uint32_t *)(import + 44) = 0x1000 + 74;
	*(uint32_t *)(import + 48) = 0x1000 + 84;

	/* this addresses will be used during compilation */
	imp_exit	= 0x400000 + 0x1000 + 40;
	imp_getchar	= 0x400000 + 0x1000 + 44;
	imp_putchar	= 0x400000 + 0x1000 + 48;
}

/*
 * Construct necessary data structures for a minimum valid PE file.
 * Create final exe file with the compiled code and dump it to file.
 */
void dump_exe(char *name)
{
	FILE *f = NULL;
	uint8_t *zero = NULL;
	uint32_t tmp32 = 0, rvacode = 0;
	uint32_t ndata = 0x2000, npe = 0x200;

	f = fopen(name, "wb");
	zero = calloc(1, ndata);
	if (f == NULL || zero == NULL) {
		exit(1);
	}

	/* DOS header. */
	fwrite("MZ", 2, 1, f);
	fwrite(zero, 0x3a, 1, f);
	fwrite("\x40\0\0\0", 4, 1, f);

	/* NT File header. PE, x86, 2 sections */
	fwrite("PE\0\0\x4C\x01\x02\0", 8, 1, f);
	fwrite(zero, 0x0c, 1, f);
	/* size of opt. header, 32 bit, exe */
	fwrite("\xE0\0\x0F\x03", 4, 1, f);

	/* Optional header. */
	fwrite("\x0B\x01\0\0", 4, 1, f);
	ncode += (4096 - (ncode % 4096));
	rvacode = ndata + 0x1000;

	/* sizeof code & init. data */
	fwrite(&ncode, sizeof(ncode), 1, f);
	fwrite(&ndata, sizeof(ndata), 1, f);
	fwrite(zero, 4, 1, f);

	/* entry point = 0x1000 */
	fwrite(&rvacode, sizeof(rvacode), 1, f);
	/* base of code & data, img base */
	fwrite(&rvacode, sizeof(rvacode), 1, f);
	fwrite("\0\x10\0\0\0\0\x40\0", 8, 1, f);

	/* section & file alignment */
	fwrite("\0\x10\0\0\0\x02\0\0", 8, 1, f);
	fwrite(zero, 0x08, 1, f);
	fwrite("\x04\0\0\0\0\0\0\0", 8, 1, f);

	/* sizeof image & headers */
	tmp32 = ncode + ndata + 0x1000;
	fwrite(&tmp32, sizeof(tmp32), 1, f);
	fwrite("\0\x02\0\0\0\0\0\0", 8, 1, f);

	/* subsystem = console */
	fwrite("\x03\0\0\0", 4, 1, f);
	/* stack & heap size */
	fwrite("\0\0\x20\0\0\x10\0\0", 8, 1, f);
	fwrite("\0\0\x10\0\0\x10\0\0", 8, 1, f);
	/* flags & #data dirs */
	fwrite("\0\0\0\0\x10\0\0\0", 8, 1, f);

	/* data directories */
	fwrite(zero, 8, 1, f);
	fwrite("\0\x10\0\0", 4, 1, f);
	fwrite(&nimport, sizeof(nimport), 1, f);
	fwrite(zero, 14 * 8, 1, f);

	/* Section headers. */
	fwrite(".data\0\0\0", 8, 1, f);
	fwrite(&ndata, sizeof(ndata), 1, f);
	fwrite("\0\x10\0\0", 4, 1, f);
	fwrite(&ndata, sizeof(ndata), 1, f);
	fwrite("\0\x02\0\0", 4, 1, f);
	fwrite(zero, 12, 1, f);	
	fwrite("\x40\0\x50\xC0", 4, 1, f);

	fwrite(".code\0\0\0", 8, 1, f);
	fwrite(&ncode, sizeof(ncode), 1, f);
	fwrite(&rvacode, sizeof(rvacode), 1, f);
	fwrite(&ncode, sizeof(ncode), 1, f);
	tmp32 = ndata + npe;
	fwrite(&tmp32, sizeof(tmp32), 1, f);
	fwrite(zero, 12, 1, f);
	fwrite("\x20\0\x50\x60", 4, 1, f);

	/* pe header ended. padding for file alignment */
	fwrite(zero, npe - ftell(f), 1, f);

	/* imports to data section */
	fwrite(import, nimport, 1, f);
	/* data section (import + data) */
	fwrite(zero, ndata - nimport, 1, f);
	/* code section */
	fwrite(code, ncode, 1, f);

	free(zero);
	fclose(f);
}

/*
 * Load brainfuck program from file to memory 'mem'.
 */
void load_program(char *file)
{
	int c, n = 0;
	FILE *f = NULL;

	f = fopen(file, "rb");
	if (!f) {
		exit(1);
	}

	while ((c = fgetc(f)) != EOF) {
		if (strchr("<>+-.,[]", c)) {
			mem[n++] = c;
		}
	}
	fclose(f);
}

/*
 * Input is file name and output is filename.exe
 */
int main(int argc, char *argv[])
{
	char out[256];

	if (argc != 2) {
		fprintf(stderr, "Usage: bfc <file>\n");
		return 1;
	}
	sprintf(out, "%.*s.exe", sizeof(out) - 1, argv[1]);
	
	code = calloc(1, 100000);
	import = calloc(1, 1024);
	if (code == NULL || import == NULL) {
		exit(1);
	}

	load_program(argv[1]);

	create_imports();

	compile();

	dump_exe(out);

	free(code);
	free(import);
	return 0;
}