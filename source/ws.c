#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "MinHook.h"
#include "ws.h"
#include "misc.h"
#include "plugins.h"
#include "list.h"

struct WS_plugins ws_plugins;
struct WS_handler ws_handlers;

typedef int (WINAPI *tWS_send)(SOCKET, const char*, int, int);
typedef int (WINAPI *tWS_recv)(SOCKET, char*, int, int);

static tWS_send origSend = NULL;
static tWS_recv  origRecv = NULL;

static int WINAPI repl_send(SOCKET s, const char *buf, int len, int flags);
static int WINAPI repl_recv(SOCKET s, char *buf, int len, int flags);

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

static DWORD WINAPI initialize(LPVOID param)
{
    if(MH_Initialize() != MH_OK) return 1;

    if(MH_CreateHookApi(L"Ws2_32.dll", "send", repl_send, (LPVOID*)&origSend) != MH_OK) return 1;
    if(MH_EnableHook(MH_ALL_HOOKS) != MH_OK) return 1;

    if(MH_CreateHookApi(L"Ws2_32.dll", "recv", repl_recv, (LPVOID*)&origRecv) != MH_OK) return 1;
    if(MH_EnableHook(MH_ALL_HOOKS) != MH_OK) return 1;

    INIT_LIST_HEAD(&ws_handlers.ws_handlers_send);
    INIT_LIST_HEAD(&ws_handlers.ws_handlers_recv);
    INIT_LIST_HEAD(&ws_plugins.plugins);

    load_plugins("./plugins/", &ws_plugins);

    return 0;
}

BOOL APIENTRY DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    switch(reason)
    {
        case DLL_PROCESS_ATTACH:
            CreateThread(NULL, 0, initialize, NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            list_for_each(t, &ws_plugins.plugins)
                FreeLibrary(list_entry(t, struct WS_plugins, plugins)->plugin);
            break;
        default:
            break;
    }
    return TRUE;
}

static int WINAPI repl_send(SOCKET s, const char *buf, int len, int flags)
{
    struct list_head *pos;
    list_for_each(pos, &ws_handlers.ws_handlers_send){
        struct WS_handler *handler = list_entry(pos, struct WS_handler, ws_handlers_send);
        if(handler && handler->func)
            handler->func(&s, buf, &len, &flags);
    }

    if(!origSend) return SOCKET_ERROR;
    return origSend(s, buf, len, flags);
}

static int WINAPI repl_recv(SOCKET s, char *buf, int len, int flags)
{
    struct list_head *pos;
    list_for_each(pos, &ws_handlers.ws_handlers_recv){
        struct WS_handler *handler = list_entry(pos, struct WS_handler, ws_handlers_recv);
        if(handler && handler->func)
            handler->func(&s, buf, &len, &flags);
    }

    if(!origRecv) return SOCKET_ERROR;
    return origRecv(s, buf, len, flags);
}
