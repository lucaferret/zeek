// $Id: IntSet.cc 80 2004-07-14 20:15:50Z jason $

#include "config.h"

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <stdlib.h>

#include "IntSet.h"

void IntSet::Expand(unsigned int i)
	{
	unsigned int newsize = i / 8 + 1;
	unsigned char* newset = new unsigned char[newsize];

	memset(newset, 0, newsize);
	memcpy(newset, set, size);

	delete [] set;
	size = newsize;
	set = newset;
	}
