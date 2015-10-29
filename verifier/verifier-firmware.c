#include "contiki.h"
#include "net/rime.h"

#include "verifier-firmware.h"

// #include "hmac_sha2.h"
#include "hmac_sha2.c"
#include "hmac_sha2.h"

#include <relic.h>

#include <stdio.h>
#include <string.h>

static void sendMsg(char* m, int len) {
  packetbuf_clear();
  packetbuf_copyfrom(m, len);
  broadcast_send(&broadcast);
}

static void copyToArray(unsigned char* from, unsigned char* to, int start, int finish) {
  int fromIndex;
  int toIndex = 0;
  for(fromIndex = start; fromIndex < finish; fromIndex++) {
    to[toIndex++] = from[fromIndex];
  }
}

static long bytesToLong(unsigned char* bytes) {
  return 
    (((long) bytes[0]) << 24) + 
    (((long) bytes[1]) << 16) +
    (((long) bytes[2]) << 8) + 
    (long) bytes[3];
}

/*---------------------------------------------------------------------------*/
PROCESS(verifier_process, "Verifier process");
AUTOSTART_PROCESSES(&verifier_process);
/*---------------------------------------------------------------------------*/

static void
broadcast_recv(struct broadcast_conn *c, const rimeaddr_t *from)
{
    printf("message received \n");
    rtimer_clock_t start = rtimer_arch_now();

    unsigned char* wholeMessage = (unsigned char*) packetbuf_dataptr();

    copyToArray(wholeMessage, IDc,      0,  8);
    copyToArray(wholeMessage, IDv,      8,  16);
    copyToArray(wholeMessage, sa,       16, 48);
    copyToArray(wholeMessage, finalSum, 48, 58);
    copyToArray(wholeMessage, tmiBytes, 58, 62);
    copyToArray(wholeMessage, mac,      62, 78);
    copyToArray(wholeMessage, giBytes,  78, 80);
    copyToArray(wholeMessage, message,  80, 80 + MSG_LENGTH);

    // for(x = 0; x < 24; x++) {
    //     printf("%i %u %u %u %u \n", x+12, wholeMessage[4*x], wholeMessage[4*x+1], wholeMessage[4*x+2], wholeMessage[4*x+3]);
    // }


    bn_t final_sum, g;

    bn_null(final_sum);
    bn_null(g);

    bn_new(final_sum);
    bn_new(g);

    bn_read_bin(final_sum, finalSum, 10);
    bn_read_bin(g, giBytes, 2);

    // printf("sa = %u %u %u %u \n", sa[0], sa[1], sa[30], sa[31]);
    // printf("message = %u %u %u %u \n", message[0], message[1], message[62], message[63]);
    // printf("final sum = %u %u %u %u \n", finalSum[0], finalSum[1], finalSum[8], finalSum[9]);
    // printf("tmi = %u %u %u %u \n", tmiBytes[0], tmiBytes[1], tmiBytes[2], tmiBytes[3]);
    // printf("mac = %u %u %u %u \n", mac[0], mac[1], mac[14], mac[15]);
    // printf("gi = %u %u \n", giBytes[0], giBytes[1]);

    tmi = bytesToLong(tmiBytes);

    // printf("tmi received = %lu, bytes = %u %u \n", tmi, tmiBytes[2], tmiBytes[3]);

    // printf("time received = %lu \n", tmi);

    ///////////////////////////////////////////////////////////////
    //////////             VERIFICATION V-1          //////////////
    ///////////////////////////////////////////////////////////////

    long currentTime = clock_time();
    if(currentTime < tmi - time_window || currentTime > tmi + time_window) {
      printf("sending tm-neg \n");
      sendMsg("tm-neg", 7);
      return;
    }

    copyToArray(finalSum, &finalSums[msgNum*10], 0, 10);

    int i, j;
    int ui_neg;
    for(i = 0; i < msgNum; i++) {
        ui_neg = 1;
        for(j = 0; j < 10; j++) {
            ui_neg = ui_neg * (finalSums[10*i + j] == finalSums[10*msgNum + j]);
            
            if(!ui_neg) {
                break;
            }
        }

        if(ui_neg) {
            sendMsg("ui-neg", 7);
            printf("sending ui-neg \n");
            return;
        }
    }

    ///////////////////////////////////////////////////////////////
    //////////             VERIFICATION V-2          //////////////
    ///////////////////////////////////////////////////////////////

    const unsigned char macInput[32 + MSG_LENGTH];
    memcpy(macInput,      IDc,          8);
    memcpy(macInput+8,    IDv,          8);
    memcpy(macInput+16,   giBytes,      2);
    memcpy(macInput+18,   finalSum,     10);
    memcpy(macInput+28,   tmiBytes,     4);
    memcpy(macInput+32,   message,      MSG_LENGTH);

    // for(x = 0; x < 10; x++) {
    //     printf("%i %u %u %u %u \n", x, macInput[4*x], macInput[4*x+1], macInput[4*x+2], macInput[4*x+3]);
    // }

    unsigned char freshMac[16];
    hmac_sha256(secret_bytes, 10, macInput, 32 + MSG_LENGTH, freshMac, 16);

    for(i = 0; i < 16; i++) {
      if(freshMac[i] != mac[i]) {
        sendMsg("MAC-neg", 8);
        printf("sending MAC-neg \n");
        return;
      }
    }

    //////////////////////////////////////////////////////////////
    //////////             VERIFICATION V-3          /////////////
    //////////////////////////////////////////////////////////////

    // int freshSum = freshUI - s - gi;
    bn_t fresh_r;
    bn_t temp;

    bn_null(fresh_r);
    bn_null(temp);
    
    bn_new(fresh_r);
    bn_new(temp);

    bn_read_bin(g, giBytes, 2);
    bn_sub(temp, final_sum, g);
    bn_sub(fresh_r, temp, s);

    unsigned char fresh_r_bytes[10] = {0x00};
    bn_write_bin(fresh_r_bytes, 10, fresh_r);

    // int size;
    // size = bn_size_bin(fresh_r);
    // printf("size of r = %i \n", size);

    // 32 bytes digest for SHA-256
    unsigned char fresh_sa[32] = {0x00};
    // printf("sum as bytes = %u%u \n", sumAsBytes[0], sumAsBytes[1]);
    md_map(fresh_sa, fresh_r_bytes, 10);

    for(i = 0; i < 32; i++) {
        // printf("%u     %u \n", freshSA[i], sa[i]);
      if(fresh_sa[i] != sa[i]) {
        sendMsg("sa-neg", 6);
        // printf("sending sa-neg \n");
        return;
      }
    }

    sendMsg("VO pos", 7);
    printf("VO pos for message %i \n", msgNum);

    betweenBroadcasts = 0;
    stop = clock_time();
    // printf("msg %i verification %lu \n", msgNum, stop - start);

    msgNum++;
    rtimer_clock_t stop = rtimer_arch_now();
    printf("ver time = %lu \n", stop - start);
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(verifier_process, ev, data)
{

  printf("this is a printf statement \n");

  static struct etimer et;
  PROCESS_EXITHANDLER(broadcast_close(&broadcast);)

  PROCESS_BEGIN();

  printf("just began process \n");

  core_init();

  bn_null(s);
  bn_new(s);
  bn_read_bin(s, secret_bytes, 10);
  
  broadcast_open(&broadcast, 129, &broadcast_call);

  printf("test \n");

  // simply open the broadcast channel and end the main process 
  // all verifier handling is done in the recv function
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
