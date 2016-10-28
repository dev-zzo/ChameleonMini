#ifndef AES_H_
#define AES_H_

#define AES_BLOCK_SIZE 		(16)


void aes_InitCryptoUnit(void);

void aes128_encrypt_block(uint8_t *plaintext, uint8_t *ciphertext, uint8_t *key);
void aes128_decrypt_block(uint8_t *ciphertext, uint8_t *plaintext, uint8_t *key);

void aes128_encrypt_cbc(uint8_t *plaintext, uint8_t *ciphertext, uint16_t length, uint8_t *key, uint8_t *iv);
void aes128_decrypt_cbc(uint8_t *ciphertext, uint8_t *plaintext, uint16_t length, uint8_t *key, uint8_t *iv);

void aes128_calcCMAC(uint8_t *msg, int16_t len, uint8_t *iv, uint8_t *aesKey);

#endif /* AES_H_ */
