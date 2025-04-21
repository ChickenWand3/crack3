#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

#if __has_include("fileutil.h")
#include "fileutil.h"
#endif

#define PASS_LEN 50     // Maximum length any password will be.
#define HASH_LEN 33     // Length of hash plus one for null.

//clang crack.c md5.c fileutil.c -lcrypto

int alphabeticalCompare(const void * a, const void * b) {
    char ** aa = (char **)a;
    char ** bb = (char **)b;

    return strcmp(*aa,*bb);
}

void addNumber(char *passwordVariant, char *password, char *digit) {
    strcpy(passwordVariant, password);
    strcat(passwordVariant, digit);
}

void addExclamantion(char *passwordVariant, char *password) {
    strcpy(passwordVariant, password);
    strcat(passwordVariant, "!");
}


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        printf("Usage: %s hash_file dictionary_file\n", argv[0]);
        exit(1);
    }

    //   TODO: Read the hashes file into an array.
    //   Use either a 2D array or an array of arrays.
    //   Use the loadFile function from fileutil.c
    //   Uncomment the appropriate statement.
    int size;
    char **hashes = loadFileAA(argv[1], &size);
    
    // CHALLENGE1: Sort the hashes using qsort.

    qsort(hashes, size, sizeof(char *), alphabeticalCompare);

    // TODO
    // Open the password file for reading.
    FILE *passwordFile = fopen(argv[2], "r");
    if (!passwordFile)
	{
	    perror("Can't open file\n");
	    exit(1);
	}

    // TODO
    // For each password, hash it, then use the array search
    char password[PASS_LEN];
    int foundCount = 0;
    int foundVariantDigits = 0;
    int foundExclamations = 0;
    while (fgets(password, PASS_LEN, passwordFile) != NULL) {
        password[strcspn(password, "\n")] = '\0';
        char *hash = md5(password, strlen(password));
        // function from fileutil.h to find the hash.
        char *found = substringSearchAA(hash, hashes, size);
        // If you find it, display the password and the hash.
        // Keep track of how many hashes were found.
        if (found) {
            foundCount++;
            printf("The password (%s) was cracked! \n Here's its hash (%s).\n", password, found);
        }
        for ( int i = 0; i < 101; i++) {
                char passwordVariant[PASS_LEN + 4];
                char digit[4];
                sprintf(digit, "%d", i);
                addNumber(passwordVariant, password, digit);
                char *hashVar = md5(passwordVariant, strlen(passwordVariant));
                char *foundVar = substringSearchAA(hashVar, hashes, size);
                if (foundVar) {
                    foundVariantDigits++;
                    printf("The password VARIANT (%s) was cracked! \n Here's its hash (%s).\n", passwordVariant, foundVar);
                }
                free(hashVar);

        }

        char passwordVariant[PASS_LEN];
        addExclamantion(passwordVariant, password);
        char *hashVar = md5(passwordVariant, strlen(passwordVariant));
        char *foundVar = substringSearchAA(hashVar, hashes, size);
        if (foundVar) {
            foundExclamations++;
            printf("The password VARIANT EXCLAMATION (%s) was cracked! \n Here's its hash (%s).\n", passwordVariant, foundVar);
        }
        free(hashVar);
        free(hash);
    }

    // CHALLENGE1: Use binary search instead of linear search.

    // TODO
    // When done with the file:
    //   Close the file
    fclose(passwordFile);
    //   Display the number of hashes found.
    printf("Normal cracked %d, Variants digits cracked %d, Exclamations cracked %d!!!!\n", foundCount, foundVariantDigits, foundExclamations);
    //   Free up memory.
    freeAA(hashes, size);
}
