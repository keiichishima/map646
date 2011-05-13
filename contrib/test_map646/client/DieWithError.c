#include <stdio.h>
#include <stdlib.h>

int DieWithError(char *errorMessage)
{
	perror(errorMessage);
	return(1);
}
