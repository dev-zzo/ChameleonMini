
#include <avr/io.h>
#include <string.h>
#include "Common.h"

#include "CryptoAES.h"


/*
1. Enable the AES interrupt (optional).
2. Select the AES direction to encryption or decryption.
3. Load the key data block into the AES key memory.
4. Load the data block into the AES state memory.
5. Start the encryption/decryption operation.
If more than one block is to be encrypted or decrypted, repeat the procedure from step 3.
 */


#define AES_CTRL_XOR_bm 		(1<<2)
#define AES_CTRL_DECRYPT_bm 	(1<<4)
#define AES_CTRL_RESET_bm 		(1<<5)
#define AES_CTRL_RUN_bm 		(1<<7)

#define AES_STATUS_ERROR_bm 	(1<<7)
#define AES_STATUS_SRIF_bm 		(1<<0)




void aes_InitCryptoUnit()
{
	AES.CTRL = AES_CTRL_RESET_bm;
}

void aes128_encrypt_block(uint8_t *plaintext, uint8_t *ciphertext, uint8_t *key)
{
	if(AES.STATUS & AES_STATUS_ERROR_bm)
		aes_InitCryptoUnit();

	//AES.CTRL = 0;

	for(uint8_t i=0; i<AES_BLOCK_SIZE; i++)
		AES.KEY = key[i];
	for(uint8_t i=0; i<AES_BLOCK_SIZE; i++)
		AES.STATE = plaintext[i];

	AES.CTRL = AES_CTRL_RUN_bm & ~AES_CTRL_DECRYPT_bm;
	while(AES.STATUS ^ AES_STATUS_SRIF_bm);

	for(uint8_t i=0; i<AES_BLOCK_SIZE; i++)
		ciphertext[i] = AES.STATE;
}

void aes128_decrypt_block(uint8_t * ciphertext, uint8_t * plaintext, uint8_t * key)
{
	static bool startup = true;
	static uint8_t lastkey[AES_BLOCK_SIZE];
	static uint8_t subkey[AES_BLOCK_SIZE];

	if(AES.STATUS & AES_STATUS_ERROR_bm)
		aes_InitCryptoUnit();

	if(startup
	|| memcmp(lastkey, key, AES_BLOCK_SIZE))
	{/* generate subkey */
		memcpy(lastkey, key, AES_BLOCK_SIZE);
		uint8_t dummy[AES_BLOCK_SIZE] = {0};
		aes128_encrypt_block(dummy, dummy, key);
		for(uint8_t i=0; i<AES_BLOCK_SIZE; i++)
			subkey[i] = AES.KEY;
		startup = false;
	}

	//AES.CTRL = AES_CTRL_DECRYPT_bm;

	for(uint8_t i=0; i<AES_BLOCK_SIZE; i++)
		AES.KEY = subkey[i];
	for(uint8_t i=0; i<AES_BLOCK_SIZE; i++)
		AES.STATE = ciphertext[i];

	AES.CTRL = AES_CTRL_RUN_bm | AES_CTRL_DECRYPT_bm;
	while(AES.STATUS ^ AES_STATUS_SRIF_bm);

	for(uint8_t i=0; i<AES_BLOCK_SIZE; i++)
		plaintext[i] = AES.STATE;
}



void aes128_encrypt_cbc(uint8_t *plaintext, uint8_t *ciphertext, uint16_t length, uint8_t *key, uint8_t *iv)
{
	// todo use XOR-function of cryptounit

	for(uint16_t i=0; i < length; i+=AES_BLOCK_SIZE) {
		for(uint8_t n=0; n < AES_BLOCK_SIZE; ++n)
			ciphertext[n+i] = plaintext[n+i] ^ iv[n];
		aes128_encrypt_block(&ciphertext[i], &ciphertext[i], key);
		memcpy(iv, &ciphertext[i], AES_BLOCK_SIZE);
	}
}

void aes128_decrypt_cbc(uint8_t *ciphertext, uint8_t *plaintext, uint16_t length, uint8_t *key, uint8_t *iv)
{
	// todo use XOR-function of cryptounit

	for(uint16_t i=0; i < length; i+=AES_BLOCK_SIZE) {
		uint8_t tmp[AES_BLOCK_SIZE]; // temporary copy of ciphertext so that cipher and plain can point to the same memory location
		memcpy(tmp, &ciphertext[i], AES_BLOCK_SIZE);
		aes128_decrypt_block(&ciphertext[i], &plaintext[i], key);
		for(uint8_t n=0; n < AES_BLOCK_SIZE; ++n)
			plaintext[n+i] ^= iv[n];
		memcpy(iv, tmp, AES_BLOCK_SIZE);
	}
}



typedef struct {
	uint8_t K1[AES_BLOCK_SIZE];
	uint8_t K2[AES_BLOCK_SIZE];
} AESCmacKey_t;

static void rotate1BitLeft(uint8_t *data, uint8_t len)
{
    for (uint8_t n = 0; n < len - 1; n++) {
		data[n] = (data[n] << 1) | (data[n+1] >> 7);
    }
    data[len - 1] <<= 1;
}

static void aes128_calcCMACSubkeys(uint8_t *aesKey, AESCmacKey_t *cmacKey)
{
    const uint8_t R = (AES_BLOCK_SIZE == 8) ? 0x1B : 0x87;
    uint8_t zeros[AES_BLOCK_SIZE] = {0};
    bool xor = false;

    // Used to compute CMAC on complete blocks
    aes128_encrypt_block(zeros, cmacKey->K1, aesKey);
    xor = cmacKey->K1[0] & 0x80;
    rotate1BitLeft(cmacKey->K1, AES_BLOCK_SIZE);
    if (xor)
    	cmacKey->K1[AES_BLOCK_SIZE-1] ^= R;

    // Used to compute CMAC on the last block if non-complete
    memcpy(cmacKey->K2, cmacKey->K1, AES_BLOCK_SIZE);
    xor = cmacKey->K2[0] & 0x80;
    rotate1BitLeft(cmacKey->K2, AES_BLOCK_SIZE);
    if (xor)
    	cmacKey->K2[AES_BLOCK_SIZE-1] ^= R;
}

/*
 * 	calculate aes-cmac in desfire style
 * 	for proper nist implementation set iv=000.. before fct-call
 */
void aes128_calcCMAC(uint8_t *msg, int16_t len, uint8_t *iv, uint8_t *aesKey)
{
	static bool startup = true;
	static AESCmacKey_t cmacKey;
	static uint8_t lastKey[AES_BLOCK_SIZE];

	if(startup
	|| memcmp(aesKey, lastKey, sizeof(lastKey)))
	{/* cmac-key expandieren */
		aes128_calcCMACSubkeys(aesKey, &cmacKey);
		memcpy(lastKey, aesKey, sizeof(lastKey));
		startup = false;
	}


    uint16_t n = 0;

    /* all but not last block */
    while(n+AES_BLOCK_SIZE < len) {
    	for(uint8_t i=0; i<AES_BLOCK_SIZE; i++)
    		iv[i] = iv[i] ^ msg[n+i];
    	aes128_encrypt_block(iv, iv, aesKey);
    	n += AES_BLOCK_SIZE;
    }

    /* last block */
    if(len%AES_BLOCK_SIZE == 0) {
    	/* complete block */
    	for(uint8_t i=0; i<AES_BLOCK_SIZE; i++)
    		iv[i] = iv[i] ^ msg[n+i] ^ cmacKey.K1[i];
    	aes128_encrypt_block(iv, iv, aesKey);
    } else {
    	/* with padding */
    	for(uint8_t i=0; i<AES_BLOCK_SIZE; i++) {
    		if(i < len%AES_BLOCK_SIZE)
    			iv[i] = iv[i] ^ msg[n+i] ^ cmacKey.K2[i];
    		else if(i == len%AES_BLOCK_SIZE)
    			iv[i] = iv[i] ^ 0x80 ^ cmacKey.K2[i];
    		else
    			iv[i] = iv[i] ^ cmacKey.K2[i];
    	}
    	aes128_encrypt_block(iv, iv, aesKey);
    }
}

