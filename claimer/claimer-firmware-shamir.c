#include "contiki.h"
#include "net/rime.h"
#include "lib/random.h"
#include "sys/clock.h"
#include "sys/etimer.h"
#include "claimer-firmware-shamir.h"
// #include "powertrace.h"

#include <relic.h>
#include <relic_md.h>

#include "hmac_sha2.h"
#include "hmac_sha2.c"

#include <stdio.h>
#include <string.h>

void randomCharArray(unsigned char *bytes, int length) {
  int i = 0;
  for(i; i < length; i++) {
    bytes[i] = rand() & 0xFF;
  }
}

void longToBytes(unsigned char *bytes, long number) {
  bytes[0] = (number >> 24) & 0xFF;
  bytes[1] = (number >> 16) & 0xFF;
  bytes[2] = (number >> 8) & 0xFF;
  bytes[3] = number & 0xFF;
}

/*---------------------------------------------------------------------------*/
PROCESS(claimer_process, "Claimer process");
AUTOSTART_PROCESSES(&claimer_process);
/*---------------------------------------------------------------------------*/
static void
initialize_message(unsigned char* wholeMessage, long currentTime, 
  unsigned char* r_bytes, unsigned char* IDc, unsigned char* IDv) {

    unsigned char* g_bytes = &G[messageNum*2];

    // 32 bytes digest for SHA-256
    unsigned char sa[32] = {0x00};
    // printf("sum as bytes = %u%u \n", sumAsBytes[0], sumAsBytes[1]);
    md_map(sa, r_bytes, 10);
    memcpy(wholeMessage+16,    sa,           32);
    // printf("sa = %u %u %u %u \n", sa[0], sa[1], sa[30], sa[31]);    

    bn_t final_sum, temp; // final_sum = R + s + g
    bn_t g, r;

    bn_null(final_sum);
    bn_null(temp);
    bn_null(r);
    bn_null(g);

    bn_new(final_sum);
    bn_new(temp);
    bn_new(r);
    bn_new(g);

    bn_read_bin(r, r_bytes, 10);
    bn_read_bin(g, g_bytes, 2);

    bn_add( temp,       s,    g);  // temp = s + gi
    bn_add( final_sum,  temp, r);   // final_sum = temp + r

    unsigned char finalSum[10] = {0x00};
    bn_write_bin(finalSum, 10, final_sum);

    memcpy(wholeMessage+48,  finalSum,     10);

    unsigned char message[MSG_LENGTH];
    randomCharArray(message, MSG_LENGTH);

    unsigned char tmi[4];
    longToBytes(tmi, currentTime);
    memcpy(wholeMessage+58,  tmi,          4);

    const unsigned char macInput[32 + MSG_LENGTH];
    memcpy(macInput,      IDc,          8);
    memcpy(macInput+8,    IDv,          8);
    memcpy(macInput+16,   g_bytes,      2);
    memcpy(macInput+18,   finalSum,     10);
    memcpy(macInput+28,   tmi,          4);
    memcpy(macInput+32,   message,      MSG_LENGTH);

    unsigned char mac[16];
    hmac_sha256(secret_bytes, 10, macInput, 32 + MSG_LENGTH, mac, 16);

  ////////////////////////////////////////////////////////////////
  /////      STEP 2 MESSAGE AUTHENTICATION INITIATION        /////
  ////////////////////////////////////////////////////////////////

    memcpy(wholeMessage,      IDc,          8);
    memcpy(wholeMessage+8,    IDv,          8); // sa, finalSum and tmi copied above
    memcpy(wholeMessage+62,   mac,          16);
    memcpy(wholeMessage+78,   g_bytes,      2);
    memcpy(wholeMessage+80,   message,      MSG_LENGTH);

    int x;
    for(x = 0; x < 28; x++) {
      // printf("%i %u %u %u %u \n", x, wholeMessage[4*x], wholeMessage[4*x+1], wholeMessage[4*x+2], wholeMessage[4*x+3]);
    }

    // printf("message = %u %u %u %u \n", message[0], message[1], message[62], message[63]);
    // printf("final sum = %u %u %u %u \n", finalSum[0], finalSum[1], finalSum[8], finalSum[9]);
    // printf("mac = %u %u %u %u \n", mac[0], mac[1], mac[14], mac[15]);
    // printf("gi = %u %u \n", g_bytes[0], g_bytes[1]);   
}

/*---------------------------------------------------------------------------*/
static void
broadcast_recv(struct broadcast_conn *c, const rimeaddr_t *from)
{
  const char* msg = (char*) packetbuf_dataptr();
  printf("broadcast received: %s \n", msg);
  // printf("length of string = %i \n", strlen(msg));

  if(strcmp(msg, "VO pos") != 0) {
    printf("terminating communication\n");
    messageNum = NUM_MSGS; // this stops the loop below
  }
}

static const struct broadcast_callbacks broadcast_call = {broadcast_recv};
static struct broadcast_conn broadcast;
/*---------------------------------------------------------------------------*/

PROCESS_THREAD(claimer_process, ev, data)
{
  static struct etimer et;
  PROCESS_EXITHANDLER(broadcast_close(&broadcast);)

  PROCESS_BEGIN();
  // powertrace_start(CLOCK_SECOND * 2);

  //////////////////////////////////////////////////////////////////
  ////////          STEP 1  INITIALIZATION                 /////////
  //////////////////////////////////////////////////////////////////

  start = clock_time();

  core_init();

  broadcast_open(&broadcast, 129, &broadcast_call);

  bn_null(s);
  bn_new(s);
  bn_read_bin(s, secret_bytes, 10);

  // claimer and verifier IPs
  static unsigned char IDc[8];
  static unsigned char IDv[8];
  randomCharArray(IDc, 8);
  randomCharArray(IDv, 8);

  stop = clock_time();

  // printf("claimer init time = %lu \n", stop - start);

  while(1) {

    long currentTime = clock_time();
    etimer_set(&et, T[messageNum] - currentTime);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    start = clock_time();

    static unsigned char message[80 + MSG_LENGTH];

    // printf("initializing message %i at time %lu \n", messageNum, start);

    initialize_message(message, T[messageNum], &r_bytes[messageNum*10], IDc, IDv);

    packetbuf_clear();

    packetbuf_copyfrom(&message[0], 80+MSG_LENGTH); // there seems to be a maximum buffer size of about 110 bytes

    printf("sending msg at time %lu \n", start);
    broadcast_send(&broadcast);

    messageNum++;

    if(messageNum == NUM_MSGS) {
      break;
    }
  }

  // printf("ending process \n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
