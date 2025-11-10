#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdint.h>
#include "../../ws.h"
#include "../../list.h"

#define LOG(x,...) do { __mingw_printf(x, ##__VA_ARGS__); __mingw_printf("\n"); } while(0)
#define LOGn(x,...) __mingw_printf(x, ##__VA_ARGS__)

#define CHUNK 262144

struct buffer_list
{
	uint64_t time;
	uint32_t size;
	uint16_t msgc;
	uint8_t flag;
	uint8_t compressed;	
	uint8_t *data;	
	struct list_head buf;
};

#pragma pack(1)
struct Pkt_FFXIV_chat
{
        uint8_t unk2[20];
        uint32_t id1;
        uint32_t unk3;
        uint32_t id2;
        uint8_t unk1;
        char name[32];
        char message[1024];
};
struct Pkt_FFXIV_chat_2
{
        uint8_t unk2[20];
        uint32_t id1;
        uint32_t unk3;
        uint32_t id2;
        char name[32];
        char message[1024];
};
struct Pkt_FFXIV_msg
{
        uint32_t msg_size;
        uint64_t entity_id;
        uint32_t unk1;
        uint32_t msg_type;
};
struct Pkt_FFXIV
{
        uint8_t unk1[16];
        uint64_t timestamp;
        uint32_t size;
        uint8_t unk2[2];
        uint16_t message_count;
        uint8_t flag1;
        uint8_t flag2;
        uint8_t unk3[6];
};
#pragma pack()

#endif //LOG_H
