#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fileutil.h"

// DIRECTIONS
// For the array of arrays, 
//    implement loadFileAA, substringSearchAA, and freeAA.


// Load the text file from the given filename.
// Return a pointer to the array of strings.
// Sets the value of size to be the number of valid
// entries in the array (not the total array length).
char ** loadFileAA(char *filename, int *size)
{
	FILE *in = fopen(filename, "r");
	if (!in)
	{
	    perror("Can't open file");
	    exit(1);
	}
	
	// TODO
	// Allocate memory for an array of strings (arr).
	int capacity = 10;
	int count = 0;
	char ** array = malloc(capacity * sizeof(char *));
	// Read the file line by line.
	char line[255];
    while(fgets(line, 255, in) != NULL) {
		//   Trim newline.
        line[strcspn(line, "\n")] = 0;
		//   Expand array if necessary (realloc).
		if (count == capacity) {
			capacity *= 2;
			array = realloc(array, capacity * sizeof(char *));
		}
		//   Allocate memory for the string (str).
		array[count] = malloc(strlen(line)+1); //+1 was to fix issue with not including \0
		//   Copy each line into the string (use strcpy).
		strcpy(array[count], line);
		count++;
	}
    // Close the file.
	fclose(in);
	
	// The size should be the number of entries in the array.
	*size = count;
	
	// Return pointer to the array of strings.
	return array;
}


int strsearch(const void *key, const void *elem){
	return strcmp((char *)key, *(char **)elem);
}

// Search the array for the target string.
// Return the found string or NULL if not found.
char * substringSearchAA(char *target, char **lines, int size)
{
    char **result = bsearch(target, lines, size, sizeof(char *), strsearch);
    return result ? *result : NULL;
}

// Free the memory used by the array
void freeAA(char ** arr, int size)
{
	for (int i = 0; i < size; i++) {
		free(arr[i]);
	}
	free(arr);
}
