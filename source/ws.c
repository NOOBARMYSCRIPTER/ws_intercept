#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#include "ws.h"
#include "misc.h"
#include "plugins.h"
#include "list.h"

#define MAX_PACKET 4096

struct WS_plugins ws_plugins;
struct WS_handler ws_handlers;

typedef int (WINAPI *tWS_send)(SOCKET, const char*, int, int);
typedef int (WINAPI *tWS_recv)(SOCKET, char*, int, int);

static DWORD WINAPI initialize(LPVOID param);
static void revert();

static int WINAPI repl_recv(SOCKET s, char *buf, int len, int flags);
static int WINAPI repl_send(SOCKET s, const char *buf, int len, int flags);

static tWS_send pSend = NULL;
static tWS_recv  pRecv = NULL;

static BYTE replaced_send[10];
static BYTE replaced_recv[10];
static uintptr_t orig_size_send = 0;
static uintptr_t orig_size_recv = 0;
static uintptr_t addr_send = 0;
static uintptr_t addr_recv = 0;

LIBAPI uintptr_t register_handler(tWS_plugin func, WS_HANDLER_TYPE type, char *comment)
{
    if(!comment) comment = (char*)"";
    struct WS_handler *t = (struct WS_handler*)malloc(sizeof(struct WS_handler));
    t->func = func;
    t->comment = (char*)malloc(strlen(comment)+1);
    strcpy(t->comment, comment);
    if(type & WS_HANDLER_SEND)
        list_add_tail(&(t->ws_handlers_send), &(ws_handlers.ws_handlers_send));
    else
        list_add_tail(&(t->ws_handlers_recv), &(ws_handlers.ws_handlers_recv));
    return (uintptr_t)t;
}

LIBAPI void unregister_handler(uintptr_t plugin_id, WS_HANDLER_TYPE type)
{
    if(!plugin_id) return;
    if(type & WS_HANDLER_SEND)
        list_del(&((struct WS_handler*)plugin_id)->ws_handlers_send);
    else
        list_del(&((struct WS_handler*)plugin_id)->ws_handlers_recv);
}

BOOL APIENTRY DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    switch(reason)
    {
        case DLL_PROCESS_ATTACH:
            CreateThread(NULL,0,initialize,NULL,0,NULL);
            break;
        case DLL_PROCESS_DETACH:
            revert();
            list_for_each(t, &ws_plugins.plugins)
                FreeLibrary(list_entry(t, struct WS_plugins, plugins)->plugin);
            break;
        default:
            break;
    }
    return TRUE;
}

static DWORD WINAPI initialize(LPVOID param)
{
    uintptr_t addr;
    BYTE replaced[10];
    uintptr_t orig_size;
    char cwdBuf[MAX_PATH], tmpPath[MAX_PATH], logPath[MAX_PATH];

    if(GetTempPathA(MAX_PATH, tmpPath)==0)
        strncpy(tmpPath, ".\\", MAX_PATH);

    if(tmpPath[strlen(tmpPath)-1]!='\\') strncat(tmpPath,"\\",MAX_PATH-strlen(tmpPath)-1);

    snprintf(logPath, MAX_PATH, "%sws_init_log.txt", tmpPath);
    FILE *dbg = fopen(logPath,"a");
    if(dbg) fprintf(dbg,"initialize start pid=%lu\n",(unsigned long)GetCurrentProcessId());

    addr_send = (uintptr_t)GetProcAddress(GetModuleHandle(TEXT("WS2_32.dll")),"send");
    addr_recv = (uintptr_t)GetProcAddress(GetModuleHandle(TEXT("WS2_32.dll")),"recv");

    if(dbg){
        if(addr_send) fprintf(dbg,"addr_send=0x%p\n",(void*)addr_send);
        if(addr_recv) fprintf(dbg,"addr_recv=0x%p\n",(void*)addr_recv);
    }

    // hook send
    addr = addr_send;
    if(apply_patch(0xE9, (SIZE_T)addr, (void*)&repl_send, (SIZE_T*)&orig_size_send, replaced_send)){
        pSend = (tWS_send)VirtualAlloc(NULL, orig_size_send+32, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(pSend){
            memcpy(pSend,replaced_send,orig_size_send);
            apply_patch(0xE9,(SIZE_T)((BYTE*)pSend+orig_size_send),(void*)(addr+orig_size_send),(SIZE_T*)&orig_size,replaced);
        }else if(dbg) fprintf(dbg,"VirtualAlloc pSend failed, err=%lu\n",GetLastError());
    }else if(dbg) fprintf(dbg,"apply_patch send failed\n");

    // hook recv
    addr = addr_recv;
    if(apply_patch(0xE9,(SIZE_T)addr,(void*)&repl_recv,(SIZE_T*)&orig_size_recv,replaced_recv)){
        pRecv = (tWS_recv)VirtualAlloc(NULL, orig_size_recv+32, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(pRecv){
            memcpy(pRecv,replaced_recv,orig_size_recv);
            apply_patch(0xE9,(SIZE_T)((BYTE*)pRecv+orig_size_recv),(void*)(addr+orig_size_recv),(SIZE_T*)&orig_size,replaced);
        }else if(dbg) fprintf(dbg,"VirtualAlloc pRecv failed, err=%lu\n",GetLastError());
    }else if(dbg) fprintf(dbg,"apply_patch recv failed\n");

    INIT_LIST_HEAD(&ws_handlers.ws_handlers_send);
    INIT_LIST_HEAD(&ws_handlers.ws_handlers_recv);
    INIT_LIST_HEAD(&ws_plugins.plugins);

    if(GetCurrentDirectoryA(MAX_PATH,cwdBuf)>0 && dbg)
        fprintf(dbg,"cwd=%s\n",cwdBuf);

    if(dbg){ fflush(dbg); fclose(dbg); }
    load_plugins("./plugins/", &ws_plugins);
    return 0;
}

static void revert()
{
    if(addr_send) exec_copy((SIZE_T)addr_send, replaced_send, orig_size_send);
    if(addr_recv) exec_copy((SIZE_T)addr_recv, replaced_recv, orig_size_recv);
}

static int WINAPI repl_send(SOCKET s, const char *buf, int len, int flags)
{
    struct list_head *pos;
    list_for_each(pos, &ws_handlers.ws_handlers_send){
        struct WS_handler *handler = list_entry(pos, struct WS_handler, ws_handlers_send);
        if(handler && handler->func)
            handler->func(&s, buf, &len, &flags);
    }
    if(!pSend) return SOCKET_ERROR;
    return pSend(s, buf, len, flags);
}

static int WINAPI repl_recv(SOCKET s, char *buf, int len, int flags)
{
    struct list_head *pos;
    list_for_each(pos, &ws_handlers.ws_handlers_recv){
        struct WS_handler *handler = list_entry(pos, struct WS_handler, ws_handlers_recv);
        if(handler && handler->func)
            handler->func(&s, buf, &len, &flags);
    }
    if(!pRecv) return SOCKET_ERROR;
    return pRecv(s, buf, len, flags);
}
