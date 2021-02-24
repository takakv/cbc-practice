#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BLOCK_SIZE 20
#define byte unsigned char

byte *gen_rand_bytestream(int byteCount) {
    byte *stream = malloc(byteCount);
    for (int i = 0; i < byteCount; ++i) stream[i] = rand();
    return stream;
}

void get_byte_array(const char *sourceText, byte *byteArray) {
    int sourceLen = (int) strlen(sourceText);
    for (int i = 0; i < sourceLen; ++i) byteArray[i] = sourceText[i];
}

void xor_byte_arrays(const byte *in1, const byte *in2, byte *out) {
    for (int i = 0; i < BLOCK_SIZE; ++i) out[i] = in1[i] ^ in2[i];
}

// Copy bytes from one byte array to another.
void bytecpy(byte *dest, const byte *src) {
    for (int i = 0; i < BLOCK_SIZE; ++i) dest[i] = src[i];
}

// For now it is the same function as above, but I separated it for future proofing.
void encdec(const byte *in, const byte *key, byte *out) {
    for (int i = 0; i < BLOCK_SIZE; ++i) out[i] = in[i] ^ key[i];
}

int main() {
    srand(time(NULL));

    // The encryption function itself is simply an XOR of a block with the key.
    // WARNING!: The code assumes that the key is longer than the block length.
    const char key[] = "This is a super secret, very very secret key!";
    const int keyLen = (int) strlen(key);
    if (keyLen < BLOCK_SIZE) {
        printf("The key must not be smaller than the block size!");
        return 1;
    }

    byte keyBytes[keyLen];
    get_byte_array(key, keyBytes);

    // Random IV, can be made public, as long as not reused.
    const byte *IV = gen_rand_bytestream(BLOCK_SIZE);

    // Excrept from "The Time Keeper", by Mitch Albom.
    const char plaintext[] = "Try to imagine a life without timekeeping. You probably can’t. You know the month, the year, the day of the week. There is a clock on your wall or the dashboard of your car. You have a schedule, a calendar, a time for dinner or a movie. Yet all around you, timekeeping is ignored. Birds are not late. A dog does not check its watch. Deer do not fret over passing birthdays. Man alone measures time. Man alone chimes the hour. And, because of this, man alone suffers a paralyzing fear that no other creature endures. A fear of time running out.";
    const int sourceLen = (int) strlen(plaintext);

    byte plaintextBytes[sourceLen];
    get_byte_array(plaintext, plaintextBytes);

    // Split plaintext into blocks, prepare blocks to store texts in.
    const int blockCount = sourceLen / BLOCK_SIZE + 1;
    byte byteBlocks[blockCount][BLOCK_SIZE];

    int bytePos = 0;
    for (int i = 0; i < blockCount; ++i) {
        for (int j = 0; j < BLOCK_SIZE; ++j) {
            byteBlocks[i][j] = plaintextBytes[bytePos++];
        }
    }

    // Get rid of potential overflow in last block.
    int padding = bytePos - sourceLen;
    for (int i = BLOCK_SIZE - padding; i < BLOCK_SIZE; ++i) {
        byteBlocks[blockCount - 1][i] = '\0';
    }

    // DEBUG: Verify blocks.
    printf("Original plaintext: %s\n", plaintext);
    printf("Plaintext blocks (concatenated): ");
    for (int i = 0; i < blockCount; ++i) {
        for (int j = 0; j < BLOCK_SIZE; ++j) {
            printf("%c", byteBlocks[i][j]);
        }
    }
    printf("\n\n");

    // CBC encryption process.
    for (int i = 0; i < blockCount; ++i) {
        // Temporarily store the result of ciphertext XOR plaintext.
        byte tempStore[BLOCK_SIZE];

        if (i == 0) {
            // XOR the first block with the IV.
            xor_byte_arrays(IV, byteBlocks[i], tempStore);
        } else {
            // XOR encryption result of previous block with current block plaintext.
            xor_byte_arrays(byteBlocks[i - 1], byteBlocks[i], tempStore);
        }

        // Encrypt the XOR result and store in the encrypted blocks.
        encdec(tempStore, keyBytes, byteBlocks[i]);
    }

    // DEBUG: Verify blocks.
    printf("Encrypted block output (hex):\n");
    for (int i = 0; i < blockCount; ++i) {
        for (int j = 0; j < BLOCK_SIZE; ++j) {
            printf("%02x", byteBlocks[i][j]);
        }
        if ((i + 1) % 3 == 0) printf("\n");
        else printf(" ");
    }
    printf("\n\n");

    // CBC decryption process.
    // Store the first encrypted block.
    byte cipherStore[BLOCK_SIZE];
    bytecpy(cipherStore, byteBlocks[0]);

    for (int i = 0; i < blockCount; ++i) {
        // Temporarily store the result of decrypted ciphertext, and its XOR with previous ciphertext.
        byte tempStore[BLOCK_SIZE], plainStore[BLOCK_SIZE];

        // Decrypt the encrypted block.
        encdec(byteBlocks[i], keyBytes, tempStore);

        if (i == 0) {
            // XOR the first decryption result with the IV.
            xor_byte_arrays(IV, tempStore, plainStore);
        } else {
            // XOR decryption result of current ciphertext block with the previous ciphertext block.
            xor_byte_arrays(cipherStore, tempStore, plainStore);
        }

        // Store the ciphertext for the next iteration.
        bytecpy(cipherStore, byteBlocks[i]);
        // Replace ciphertext with plaintext.
        bytecpy(byteBlocks[i], plainStore);
    }

    // DEBUG: Verify blocks.
    printf("Decrypted blocks (concatenated):\n");
    for (int i = 0; i < blockCount; ++i) {
        for (int j = 0; j < BLOCK_SIZE; ++j) {
            printf("%c", byteBlocks[i][j]);
        }
    }

    return 0;
}
