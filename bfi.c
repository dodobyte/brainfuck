#include <stdio.h>
#include <string.h>

char mem[10000];

void interpret()
{
	char *pc  = mem;					/* code 0-5k   */
	char *ptr = mem + 5000;				/* data 5-9k   */
	char **sp = (char **)(mem + 9000);	/* stack 9-10k */

	while (*pc) {
		
		switch (*pc++) {
		case '>':
			ptr++;
			break;
		case '<':
			ptr--;
			break;
		case '+':
			++*ptr;
			break;
		case '-':
			--*ptr;
			break;
		case '.':
			putchar(*ptr);
			break;
		case ',':
			*ptr = getchar();
			break;
		case '[':
			if (*ptr == 0) {
				int c, depth = 0;

				while ((c = *pc++)) {
					if (c == '[') {
						depth++;
					} else if (c == ']') {
						if (depth-- == 0) {
							break;
						}
					}
				}
			} else {
				*sp++ = pc - 1;
			}
			break;
		case ']':
			pc = *--sp;
			break;
		}
	}
}

int main(int argc, char *argv[])
{
	int c, n = 0;
	FILE *f = NULL;

	if (argc != 2) {
		return 1;
	}

	f = fopen(argv[1], "rb");
	if (!f) {
		return 1;
	}

	while ((c = fgetc(f)) != EOF) {
		if (strchr("<>+-.,[]", c)) {
			mem[n++] = c;
		}
	}
	fclose(f);

	interpret();

	return 0;
}