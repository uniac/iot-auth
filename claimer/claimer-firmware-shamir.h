#include <relic.h>

#define NUM_MSGS 10
#define MSG_LENGTH 16

const static unsigned char secret_bytes[10] = {0x19, 0xC4, 0x89, 0xCD, 0xCD, 0xD6, 0xB7, 0xC3, 0xA5, 0x58};
static bn_t s;

static long start, stop;

static int x;

// random bytes reserved for G
const static unsigned char G[20] = {
  0xcc, 0x48, 
  0x5c, 0xbf, 
  0x8d, 0x36, 
  0x4a, 0x87, 
  0x0a, 0xfc, 
  0xfa, 0x12, 
  0x15, 0x3a, 
  0xf4, 0x6c, 
  0x90, 0x75, 
  0xae, 0xff
  };

const static long T[10] = {1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000};

const static unsigned char r_bytes[100] = {
  0x07, 0xa3, 0x48, 0xba, 0x7c, 0x1b, 0xfb, 0x45, 0x5a, 0xe1, 
  0x0b, 0x42, 0xb3, 0x00, 0xfd, 0xa3, 0x80, 0x46, 0x46, 0xd1, 
  0x02, 0xd6, 0x07, 0x05, 0xf1, 0x9b, 0xc7, 0x72, 0x08, 0x02, 
  0x05, 0x0e, 0x8c, 0x8f, 0xf9, 0x8d, 0x88, 0xc2, 0xc4, 0x16,
  0x0c, 0x6d, 0x04, 0x4f, 0x74, 0x25, 0xc0, 0x6b, 0x32, 0xf0, 
  0x09, 0x7b, 0x23, 0x03, 0xd5, 0xe3, 0xf4, 0xd2, 0x07, 0x05, 
  0x01, 0x32, 0xa4, 0x81, 0x4d, 0x8c, 0x0f, 0x4d, 0x80, 0xa3, 
  0x07, 0x72, 0x84, 0x9b, 0xe1, 0xcc, 0x0f, 0xe5, 0x76, 0xd0,
  0x04, 0x86, 0x67, 0xab, 0xda, 0xc4, 0x1f, 0x74, 0x0d, 0xed, 
  0x06, 0x69, 0x55, 0xfa, 0xd1, 0xcf, 0xc9, 0xd5, 0x72, 0x39
};

void randomCharArray(unsigned char *bytes, int length);

static int messageNum = 0;

void intToBytes(unsigned char *bytes, unsigned int number);

void longToBytes(unsigned char *bytes, long number);