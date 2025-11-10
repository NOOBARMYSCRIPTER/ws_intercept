#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "include/MinHook.h"
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
    // Небольшая пауза, чтобы DllMain успел вернуться и освободить loader lock.
    Sleep(200);

    char tmpPath[MAX_PATH];
    char logPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tmpPath) == 0) {
        strncpy(tmpPath, ".\\", MAX_PATH);
    }
    if (tmpPath[strlen(tmpPath)-1] != '\\')
        strncat(tmpPath, "\\", MAX_PATH - strlen(tmpPath) - 1);
    snprintf(logPath, MAX_PATH, "%sws_init_log.txt", tmpPath);

    FILE *dbg = fopen(logPath, "a");
    if (!dbg) {
        dbg = fopen("ws_init_log.txt", "a");
    }
    if (dbg) {
        fprintf(dbg, "== initialize start, pid=%lu ==\n", (unsigned long)GetCurrentProcessId());
        fflush(dbg);
    }

    HMODULE hMin = GetModuleHandleW(L"MinHook.x64.dll");
    if (!hMin) {
        if (dbg) fprintf(dbg, "MinHook.x64.dll not in process. Try LoadLibrary...\n");
        hMin = LoadLibraryW(L"MinHook.x64.dll");
        if (!hMin) {
            if (dbg) fprintf(dbg, "LoadLibrary(MinHook.x64.dll) failed, GetLastError=%lu\n", (unsigned long)GetLastError());
            if (dbg) { fflush(dbg); fclose(dbg); }
            return 1;
        } else {
            if (dbg) fprintf(dbg, "Loaded MinHook.x64.dll ok.\n");
        }
    } else {
        if (dbg) fprintf(dbg, "MinHook.x64.dll already loaded.\n");
    }

    uintptr_t addr_send = (uintptr_t)GetProcAddress(GetModuleHandle(TEXT("Ws2_32.dll")), "send");
    uintptr_t addr_recv = (uintptr_t)GetProcAddress(GetModuleHandle(TEXT("Ws2_32.dll")), "recv");
    if (dbg) {
        fprintf(dbg, "addr_send=%p, addr_recv=%p\n", (void*)addr_send, (void*)addr_recv);
    }

    MH_STATUS st;
    st = MH_Initialize();
    if (dbg) fprintf(dbg, "MH_Initialize => %d\n", (int)st);
    if (st != MH_OK) {
        if (dbg) { fflush(dbg); fclose(dbg); }
        return 1;
    }

    st = MH_CreateHookApi(L"Ws2_32.dll", "send", (LPVOID)repl_send, (LPVOID*)&origSend);
    if (dbg) fprintf(dbg, "MH_CreateHookApi(send) => %d\n", (int)st);
    if (st != MH_OK) {
        MH_Uninitialize();
        if (dbg) { fflush(dbg); fclose(dbg); }
        return 1;
    }

    st = MH_CreateHookApi(L"Ws2_32.dll", "recv", (LPVOID)repl_recv, (LPVOID*)&origRecv);
    if (dbg) fprintf(dbg, "MH_CreateHookApi(recv) => %d\n", (int)st);
    if (st != MH_OK) {
        MH_RemoveHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        if (dbg) { fflush(dbg); fclose(dbg); }
        return 1;
    }

    st = MH_EnableHook(MH_ALL_HOOKS);
    if (dbg) fprintf(dbg, "MH_EnableHook(MH_ALL_HOOKS) => %d\n", (int)st);
    if (st != MH_OK) {
        MH_RemoveHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        if (dbg) { fflush(dbg); fclose(dbg); }
        return 1;
    }

    INIT_LIST_HEAD(&ws_handlers.ws_handlers_send);
    INIT_LIST_HEAD(&ws_handlers.ws_handlers_recv);
    INIT_LIST_HEAD(&ws_plugins.plugins);

    if (dbg) {
        char cwd[MAX_PATH];
        if (GetCurrentDirectoryA(MAX_PATH, cwd) > 0)
            fprintf(dbg, "Calling load_plugins, cwd=%s\n", cwd);
        fflush(dbg);
    }

    load_plugins("./plugins/", &ws_plugins);

    if (dbg) {
        fprintf(dbg, "load_plugins returned. initialize finished.\n\n");
        fflush(dbg);
        fclose(dbg);
    }

    return 0;
}

BOOL APIENTRY DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    switch(reason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(instance);
            CreateThread(NULL, 0, initialize, NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            // Отключаем хуки и выгружаем плагины
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
