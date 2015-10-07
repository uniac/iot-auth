#include <relic.h>

#define MSG_LENGTH 16
#define time_window 300 // 300/128 = 2.3 seconds

const static unsigned char secret_bytes[10] = {0x19, 0xC4, 0x89, 0xCD, 0xCD, 0xD6, 0xB7, 0xC3, 0xA5, 0x58};
static bn_t s;

static int msgNum = 0;
static int betweenBroadcasts = 0; // since the broadcast is in 2 parts

static unsigned char IDc[8];
static unsigned char IDv[8];
static unsigned char sa[32];
static unsigned char message[MSG_LENGTH];
static unsigned char tmiBytes[4];
static unsigned char giBytes[2];
static unsigned char finalSum[10];
static unsigned char finalSums[100];
static long tmi;
static unsigned char mac[16];
static int gi;

static int x;

static long start, stop;

static bn_t s;

static int bytesToInt(unsigned char* bytes);

static void copyToArray(unsigned char* from, unsigned char* to, int start, int finish);

static struct broadcast_conn broadcast;
static void broadcast_recv(struct broadcast_conn *c, const rimeaddr_t *from);
static const struct broadcast_callbacks broadcast_call = {broadcast_recv};

static void sendMsg(char* m, int len);
