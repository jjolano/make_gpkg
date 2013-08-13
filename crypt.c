// from ps3py
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

void keyToContext(uint8_t key[0x10], uint8_t largekey[0x40])
{
	memset(largekey, 0, 0x40);

	memcpy(largekey,		key, 8);
	memcpy(largekey+0x8,	key, 8);
	memcpy(largekey+0x10,	key+0x8, 8);
	memcpy(largekey+0x18,	key+0x8, 8);
}

void setContextNum(uint8_t largekey[0x40])
{
	memset(largekey+0x38,	0xff, 8);
}

void manipulate(uint8_t key[0x40])
{
	/* We need to cast each byte to a 64 bit int so that gcc won't truncate it
	 down to a 32 bit in before shifting */
	uint64_t temp = ((uint64_t) key[0x38]) << 56|
	((uint64_t) key[0x39]) << 48|
	((uint64_t) key[0x3a]) << 40|
	((uint64_t) key[0x3b]) << 32|
	key[0x3c] << 24|
	key[0x3d] << 16|
	key[0x3e] <<  8|
	key[0x3f];
	temp++;
	key[0x38] = (temp >> 56) & 0xff;
	key[0x39] = (temp >> 48) & 0xff;
	key[0x3a] = (temp >> 40) & 0xff;
	key[0x3b] = (temp >> 32) & 0xff;
	key[0x3c] = (temp >> 24) & 0xff;
	key[0x3d] = (temp >> 16) & 0xff;
	key[0x3e] = (temp >>  8) & 0xff;
	key[0x3f] = (temp >>  0) & 0xff;
}

void pkg_crypt(uint8_t largekey[0x40], uint8_t* input, int length)
{
	int i, offset = 0;

	while(length > 0)
	{
		int bytes_to_dump = length;
		if(bytes_to_dump > 0x10)
			bytes_to_dump = 0x10;

		uint8_t outHash[SHA_DIGEST_LENGTH];
		SHA1(largekey, 0x40, outHash);

		for(i = 0; i < bytes_to_dump; i++)
		{
			input[offset] = outHash[i] ^ input[offset];
			offset++;
		}

		manipulate(largekey);
		length -= bytes_to_dump;
	}
}
