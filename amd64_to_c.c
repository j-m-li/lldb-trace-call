/* 
 * The author disclaims copyright to this source code.
 */

#include <stdio.h>
#include <stdlib.h>

FILE *fi;
FILE *fo;

int main(int argc, char *argv[])
{
	char c;
	fi = fopen("log.txt", "r");
	fo = fopen("prog.c", "w");

	while (fread(&c, 1, 1, fi) == 1) {
		fwrite(&c, 1, 1, fo);
	}

	fclose(fi);
	fclose(fo);
	return 0;
}

