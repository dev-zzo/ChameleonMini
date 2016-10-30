#ifndef AES_H_
#define AES_H_

#define AES_BLOCK_SIZE      (16)


void CryptoAESInitCryptoUnit(void);

void CryptoAES128EncryptBlock(uint8_t *Plaintext, uint8_t *Ciphertext, uint8_t *Key);
void CryptoAES128DecryptBlock(uint8_t *Ciphertext, uint8_t *Plaintext, uint8_t *Key);

void CryptoAES128EncryptCBC(uint8_t *Plaintext, uint8_t *Ciphertext, uint16_t length, uint8_t *Key, uint8_t *InitialVector);
void CryptoAES128DecryptCBC(uint8_t *Ciphertext, uint8_t *Plaintext, uint16_t length, uint8_t *Key, uint8_t *InitialVector);

void CryptoAES128CalcCMAC(uint8_t *Message, int16_t Length, uint8_t *InitialVector, uint8_t *Key);

#endif /* AES_H_ */
