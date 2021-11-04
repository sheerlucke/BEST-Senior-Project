//Encryption block for BEST project by JC Harding, Aki Miyake, David Liu
//Case Western Reserve University, Fall 2021
//based on https://github.com/suculent/thinx-aes-lib/tree/master/examples/simple

#include "AESLib.h"
#define BAUD 9600
#define INPUT_BUFFER_LIMIT (128 + 1) // designed for Arduino UNO
AESLib aesLib;

//Input message goes here
unsigned char readBuffer[25] = "BEST Senior Project";

unsigned char cleartext[INPUT_BUFFER_LIMIT] = {0}; // input buffer for text
unsigned char ciphertext[2*INPUT_BUFFER_LIMIT] = {0}; // output buffer for base-64 encoded encrypted data

// AES Encryption Key (keep it secret! keep it safe!)
byte aes_key[] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };

//Initialization Vector
byte aes_iv[N_BLOCK] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };

//Working Vector Buffer (Copied from Initialization vector before encryption/decryption)
byte working_iv[N_BLOCK] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };

//Print vector function
void print_vector(byte vector[]) {
  for (int i = 0; i < 16; i++) {
    Serial.print(vector[i], HEX);
    Serial.print("  ");
  }
  Serial.println();
}

//Randomize aes_iv function
void rand_aes(byte iv[]) {
  for (int i = 0; i < 16; i++) {
    iv[i] = random(1, 256);
  }
}

//Encryption function
uint16_t encrypt_to_ciphertext(char * msg, uint16_t msgLen, byte iv[]) {
  Serial.println("Calling encrypt...");
  // aesLib.get_cipher64_length(msgLen);
  int cipherlength = aesLib.encrypt((byte*)msg, msgLen, (char*)ciphertext, aes_key, sizeof(aes_key), iv);
                   // uint16_t encrypt(byte input[], uint16_t input_length, char * output, byte key[],int bits, byte my_iv[]);
  return cipherlength;
}

//Decryption function
uint16_t decrypt_to_cleartext(byte msg[], uint16_t msgLen, byte iv[]) {
  Serial.println("Calling decrypt...; ");
  uint16_t dec_bytes = aesLib.decrypt(msg, msgLen, (char*)cleartext, aes_key, sizeof(aes_key), iv);
  return dec_bytes;
}


void setup() {
  Serial.begin(BAUD);
  Serial.setTimeout(60000);
  randomSeed(analogRead(A1));
  delay(2000);

  aesLib.set_paddingmode((paddingMode)0);
  rand_aes(aes_iv);
}

void loop() {
  //Print AES key and IV for debugging
  Serial.println("AES key vector: ");
  print_vector(aes_key);
  Serial.println("AES IV: ");
  print_vector(aes_iv);
  
  //Pull string from readBuffer
  sprintf((char*)cleartext, "%s", readBuffer);
  Serial.print("Input message is: "); Serial.println((char*)cleartext);
  Serial.println("\nBeginning encryption...");

  //Encryption Stage (Only doing one stage of encryption for simplicity)
  //Copy the aes_iv to the working_iv so we can save the original IV
  //We will use the original IV for decryption
  memcpy(working_iv, aes_iv, sizeof(aes_iv));

  //Encrypt
  uint16_t msgLen = sizeof(readBuffer);
  uint16_t encLen = encrypt_to_ciphertext((char*)cleartext, msgLen, working_iv);
  Serial.print("Encrypted message: "); Serial.println((char*)ciphertext);

  //Decrypt
  Serial.println("\nBeginning decryption...");

  //Decode the base64 message
  unsigned char base64decoded[50] = {0};
  base64_decode((char*)base64decoded, (char*)ciphertext, encLen);

  //Copy the IV from aes_iv to working_iv
  memcpy(working_iv, aes_iv, sizeof(aes_iv));

  decrypt_to_cleartext(base64decoded, strlen((char*)base64decoded), working_iv);
  Serial.print("Decrypted cleartext: "); Serial.println((char*)cleartext);

  if (strcmp((char*)readBuffer, (char*)cleartext) == 0) {
    Serial.println("Decrypted correctly.");
  } else {
    Serial.println("Decryption test failed.");
  }

  Serial.println("----------");
  delay(5000);
}
