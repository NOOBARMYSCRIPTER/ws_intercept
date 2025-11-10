#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <zlib.h>
#include <stdlib.h>
#include "log.h"

static DWORD WINAPI setup_console(LPVOID param);

void WINAPI log_ws(SOCKET *s, const char *buf, int *len, int *flags);
int UncompressData(const unsigned char* abSrc, int nLenSrc, unsigned char* abDst, int nLenDst);

static DWORD threadIDConsole = 0;
static DWORD plugin_id_recv = 0;

#define CHUNK 262144

#pragma pack(1)
struct Pkt_FFXIV_chat
{
    uint8_t unk2[20];
    uint32_t id1;
    uint32_t unk3;
    uint32_t id2;
    uint8_t unk1;
    unsigned char name[32];
    unsigned char message[1024];
};
struct Pkt_FFXIV_chat_2
{
    uint8_t unk2[20];
    uint32_t id1;
    uint32_t unk3;
    uint32_t id2;
    unsigned char name[32];
    unsigned char message[1024];
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
    unsigned char *data;
};
#pragma pack()

BOOL APIENTRY DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    switch(reason)
    {
        case DLL_PROCESS_ATTACH:
            plugin_id_recv = register_handler(log_ws, WS_HANDLER_RECV, "A logging function for ws2_recv");
            CreateThread(NULL, 0, setup_console, NULL, 0, &threadIDConsole);
            break;
        case DLL_PROCESS_DETACH:
            unregister_handler(plugin_id_recv, WS_HANDLER_RECV);
            if(threadIDConsole)
                PostThreadMessage(threadIDConsole, WM_QUIT, 0, 0);
            break;
        case DLL_THREAD_ATTACH: break;
        case DLL_THREAD_DETACH: break;
    }
    return TRUE;
}

inline void handle_chat(unsigned char *buf, size_t size)
{
    struct Pkt_FFXIV_chat *chat = malloc(sizeof(struct Pkt_FFXIV_chat));
    memcpy(chat, buf, size);
    LOGn("Message Size: %zu ", size);
    LOG("[%s][%u %u]: %s", chat->name, chat->id1, chat->id2, chat->message);
    free(chat);
}

inline void handle_chat_2(unsigned char *buf, size_t size)
{
    struct Pkt_FFXIV_chat_2 *chat = malloc(sizeof(struct Pkt_FFXIV_chat_2));
    memcpy(chat, buf, size);
    LOGn("Message Size: %zu ", size);
    LOG("[%s][%u %u]: %s", chat->name, chat->id1, chat->id2, chat->message);
    free(chat);
}

void WINAPI log_ws(SOCKET *s, const char *buf, int *len, int *flags)
{
    if(!*len || *len < (sizeof(struct Pkt_FFXIV)-sizeof(unsigned char*)))
        return;

    struct Pkt_FFXIV packet;
    uintptr_t pos = (uintptr_t)buf;

    memcpy(&packet, (void*)pos, sizeof(struct Pkt_FFXIV) - sizeof(unsigned char*));
    pos += sizeof(struct Pkt_FFXIV) - sizeof(unsigned char*);

    if(packet.size < 19)
        return;

    size_t to_read = *len - (sizeof(struct Pkt_FFXIV) - sizeof(unsigned char*));
    packet.data = malloc(to_read);
    memcpy(packet.data, (void*)pos, to_read);
    pos += to_read;

    if(packet.flag2)
    {
        unsigned char *t_data = malloc(CHUNK);
        UncompressData(packet.data, to_read, t_data, CHUNK);
        free(packet.data);
        packet.data = t_data;
    }

    pos = (uintptr_t)(packet.data);
    while(packet.message_count--)
    {
        struct Pkt_FFXIV_msg *msg = malloc(sizeof(struct Pkt_FFXIV_msg));
        memcpy(msg, (void*)pos, sizeof(struct Pkt_FFXIV_msg));
        pos += sizeof(struct Pkt_FFXIV_msg);

        switch(msg->msg_type)
        {
            case 0x00650014: handle_chat((unsigned char*)pos, msg->msg_size); break;
            case 0x00670014: handle_chat_2((unsigned char*)pos, msg->msg_size); break;
            default: break;
        }

        pos += msg->msg_size;
        free(msg);
    }

    free(packet.data);
}

static DWORD WINAPI setup_console(LPVOID param)
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONIN$", "r", stdin);
    while(1)
    {
        MSG msg;
        if(PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        {
            if(msg.message == WM_QUIT)
            {
                FreeConsole();
                return msg.wParam;
            }
        }
    }
    return 0;
}

int UncompressData(const unsigned char* abSrc, int nLenSrc, unsigned char* abDst, int nLenDst)
{
    z_stream zInfo = {0};
    zInfo.total_in = zInfo.avail_in = nLenSrc;
    zInfo.avail_out = nLenDst;
    zInfo.next_in = (unsigned char*)abSrc;
    zInfo.next_out = abDst;

    int nErr, nRet = -1;
    nErr = inflateInit(&zInfo);
    if(nErr == Z_OK)
    {
        nErr = inflate(&zInfo, Z_FINISH);
        if(nErr == Z_STREAM_END)
            nRet = zInfo.total_out;
    }
    inflateEnd(&zInfo);
    return nRet;
}
