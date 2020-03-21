//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

/* 
 *  This is just a portion of original file with only 32-bit version
 *  of MurmurHash3.
 */

#ifndef _MURMURHASH3_H_
#define _MURMURHASH3_H_

#include <stdint.h>

//-----------------------------------------------------------------------------

void MurmurHash3_x86_32  ( const void * key, int len, uint32_t seed, void * out );

#endif // _MURMURHASH3_H_