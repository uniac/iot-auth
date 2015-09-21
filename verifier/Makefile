all: verifier-firmware
CONTIKI=../../..

RELIC_SOURCE = /home/user/Desktop/relic-0.4.0
RELIC_TARGET = /home/user/Desktop/relic-target-4-s256
CFLAGS += -l$(RELIC_SOURCE)/include -l$(RELIC_TARGET)/include -Os
CFLAGS += -I$(RELIC_SOURCE)/include -I$(RELIC_TARGET)/include -Os
CFLAGS += -I/usr/msp430/include
PROJECT_LIBRARIES += $(RELIC_TARGET)/lib/librelic_s.a

include $(CONTIKI)/Makefile.include

PROJECT_LIBRARIES+= hmac_and_sha.a
CONTIKI_SOURCEFILES += sha2.c hmac_sha2.c
