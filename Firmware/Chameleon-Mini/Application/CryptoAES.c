
#include <avr/io.h>
#include <string.h>
#include "Common.h"

#include "CryptoAES.h"


/*
 * 1. Enable the AES interrupt (optional).
 * 2. Select the AES direction to encryption or decryption.
 * 3. Load the key data block into the AES key memory.
 * 4. Load the data block into the AES state memory.
 * 5. Start the encryption/decryption operation.
 * If more than one block is to be encrypted or decrypted, repeat the procedure from step 3.
 */


#define AES_CTRL_XOR_bm         (1<<2)
#define AES_CTRL_DECRYPT_bm     (1<<4)
#define AES_CTRL_RESET_bm       (1<<5)
#define AES_CTRL_RUN_bm         (1<<7)

#define AES_STATUS_ERROR_bm     (1<<7)
#define AES_STATUS_SRIF_bm      (1<<0)




void CryptoAESInitCryptoUnit()
{
    AES.CTRL = AES_CTRL_RESET_bm;
}

void CryptoAES128EncryptBlock(uint8_t *Plaintext, uint8_t *Ciphertext, uint8_t *Key)
{
    if (AES.STATUS & AES_STATUS_ERROR_bm)
        CryptoAESInitCryptoUnit();

    //AES.CTRL = 0;

    for (uint8_t i=0; i<AES_BLOCK_SIZE; i++)
        AES.KEY = Key[i];
    for (uint8_t i=0; i<AES_BLOCK_SIZE; i++)
        AES.STATE = Plaintext[i];

    AES.CTRL = AES_CTRL_RUN_bm & ~AES_CTRL_DECRYPT_bm;
    while ((AES.STATUS & AES_STATUS_SRIF_bm) == 0);

    for (uint8_t i=0; i<AES_BLOCK_SIZE; i++)
        Ciphertext[i] = AES.STATE;
}

void CryptoAES128DecryptBlock(uint8_t * Ciphertext, uint8_t * Plaintext, uint8_t * Key)
{
    static bool Startup = true;
    static uint8_t LastKey[AES_BLOCK_SIZE];
    static uint8_t SubKey[AES_BLOCK_SIZE];

    if (AES.STATUS & AES_STATUS_ERROR_bm)
        CryptoAESInitCryptoUnit();

    if (Startup || memcmp(LastKey, Key, AES_BLOCK_SIZE)) {
        /* generate subkey */
        memcpy(LastKey, Key, AES_BLOCK_SIZE);
        uint8_t dummy[AES_BLOCK_SIZE] = {0};
        CryptoAES128EncryptBlock(dummy, dummy, Key);
        for (uint8_t i=0; i<AES_BLOCK_SIZE; i++)
            SubKey[i] = AES.KEY;
        Startup = false;
    }

    //AES.CTRL = AES_CTRL_DECRYPT_bm;

    for (uint8_t i=0; i<AES_BLOCK_SIZE; i++)
        AES.KEY = SubKey[i];
    for (uint8_t i=0; i<AES_BLOCK_SIZE; i++)
        AES.STATE = Ciphertext[i];

    AES.CTRL = AES_CTRL_RUN_bm | AES_CTRL_DECRYPT_bm;
    while ((AES.STATUS & AES_STATUS_SRIF_bm) == 0);

    for (uint8_t i=0; i<AES_BLOCK_SIZE; i++)
        Plaintext[i] = AES.STATE;
}



void CryptoAES128EncryptCBC(uint8_t *Plaintext, uint8_t *Ciphertext, uint16_t Length, uint8_t *Key, uint8_t *InitialVector)
{
    /* todo use XOR-function of cryptounit */

    for (uint16_t i=0; i < Length; i+=AES_BLOCK_SIZE) {
        for (uint8_t n=0; n < AES_BLOCK_SIZE; ++n)
            Ciphertext[n + i] = Plaintext[n + i] ^ InitialVector[n];
        CryptoAES128EncryptBlock(&Ciphertext[i], &Ciphertext[i], Key);
        memcpy(InitialVector, &Ciphertext[i], AES_BLOCK_SIZE);
    }
}

void CryptoAES128DecryptCBC(uint8_t *Ciphertext, uint8_t *Plaintext, uint16_t Length, uint8_t *Key, uint8_t *InitialVector)
{
    /* todo use XOR-function of cryptounit */

    for (uint16_t i=0; i < Length; i+=AES_BLOCK_SIZE) {
        uint8_t TempCipher[AES_BLOCK_SIZE];
        memcpy(TempCipher, &Ciphertext[i], AES_BLOCK_SIZE);
        CryptoAES128DecryptBlock(&Ciphertext[i], &Plaintext[i], Key);
        for (uint8_t n=0; n < AES_BLOCK_SIZE; ++n)
            Plaintext[n + i] ^= InitialVector[n];
        memcpy(InitialVector, TempCipher, AES_BLOCK_SIZE);
    }
}



typedef struct {
    uint8_t K1[AES_BLOCK_SIZE];
    uint8_t K2[AES_BLOCK_SIZE];
} AESCmacKeyType;

static void Rotate1BitLeft(uint8_t *Data, uint8_t Length)
{
    for (uint8_t n = 0; n < Length - 1; n++) {
        Data[n] = (Data[n] << 1) | (Data[n+1] >> 7);
    }
    Data[Length - 1] <<= 1;
}

static void CryptoAES128CalcCMACSubkeys(uint8_t *AESKey, AESCmacKeyType *CmacKey)
{
    const uint8_t R = (AES_BLOCK_SIZE == 8) ? 0x1B : 0x87;
    uint8_t Zeros[AES_BLOCK_SIZE] = {0};
    bool Xor = false;

    /* Used to compute CMAC on complete blocks */
    CryptoAES128EncryptBlock(Zeros, CmacKey->K1, AESKey);
    Xor = CmacKey->K1[0] & 0x80;
    Rotate1BitLeft(CmacKey->K1, AES_BLOCK_SIZE);
    if (Xor)
        CmacKey->K1[AES_BLOCK_SIZE-1] ^= R;

    /* Used to compute CMAC on the last block if non-complete */
    memcpy(CmacKey->K2, CmacKey->K1, AES_BLOCK_SIZE);
    Xor = CmacKey->K2[0] & 0x80;
    Rotate1BitLeft(CmacKey->K2, AES_BLOCK_SIZE);
    if (Xor)
        CmacKey->K2[AES_BLOCK_SIZE-1] ^= R;
}

/*
 *     calculate aes-cmac in desfire style
 *     for proper nist implementation set iv=000.. before fct-call
 */
void CryptoAES128CalcCMAC(uint8_t *Message, int16_t Length, uint8_t *InitialVector, uint8_t *Key)
{
    static bool Startup = true;
    static AESCmacKeyType cmacKey;
    static uint8_t LastKey[AES_BLOCK_SIZE];

    if (Startup || memcmp(Key, LastKey, sizeof(LastKey))) {
        /* expand cmac-key */
        CryptoAES128CalcCMACSubkeys(Key, &cmacKey);
        memcpy(LastKey, Key, sizeof(LastKey));
        Startup = false;
    }

    uint16_t n = 0;

    /* all but not last block */
    while ((n + AES_BLOCK_SIZE) < Length) {
        for (uint8_t i=0; i<AES_BLOCK_SIZE; i++)
            InitialVector[i] = InitialVector[i] ^ Message[n + i];
        CryptoAES128EncryptBlock(InitialVector, InitialVector, Key);
        n += AES_BLOCK_SIZE;
    }

    /* last block */
    if (Length % AES_BLOCK_SIZE == 0) {
        /* complete block */
        for (uint8_t i=0; i<AES_BLOCK_SIZE; i++)
            InitialVector[i] = InitialVector[i] ^ Message[n + i] ^ cmacKey.K1[i];
        CryptoAES128EncryptBlock(InitialVector, InitialVector, Key);
    } else {
        /* with padding */
        for (uint8_t i=0; i<AES_BLOCK_SIZE; i++) {
            if (i < Length%AES_BLOCK_SIZE)
                InitialVector[i] = InitialVector[i] ^ Message[n + i] ^ cmacKey.K2[i];
            else if (i == Length%AES_BLOCK_SIZE)
                InitialVector[i] = InitialVector[i] ^ 0x80 ^ cmacKey.K2[i];
            else
                InitialVector[i] = InitialVector[i] ^ cmacKey.K2[i];
        }
        CryptoAES128EncryptBlock(InitialVector, InitialVector, Key);
    }
}

