#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "log.h"

static DWORD WINAPI setup_console(LPVOID param);
static DWORD WINAPI console_handler(LPVOID param);

void WINAPI log_ws(SOCKET *s, const char *buf, int *len, int *flags);

static DWORD threadIDConsole = 0;
static DWORD plugin_id_send = 0;
static DWORD plugin_id_recv = 0;

BOOL APIENTRY DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	switch(reason)
	{
		case DLL_PROCESS_ATTACH:
			CreateThread(NULL,0,setup_console,NULL,0,&threadIDConsole);
			break;
		case DLL_PROCESS_DETACH:
			unregister_handler(plugin_id_send, WS_HANDLER_SEND);
			unregister_handler(plugin_id_recv, WS_HANDLER_RECV);
			if (threadIDConsole)
				PostThreadMessage(threadIDConsole, WM_QUIT, 0, 0);
			break;
		case DLL_THREAD_ATTACH: break;
		case DLL_THREAD_DETACH: break;
	}
	return TRUE;
}

void WINAPI log_ws(SOCKET *s, const char *buf, int *len, int *flags)
{
	struct sockaddr_in info;
	socklen_t infolen = sizeof(info);
	getpeername(*s, (struct sockaddr*)&info, &infolen);
	const uint16_t port = ntohs(info.sin_port);

#if LOGGING == 1
	LOG(s, sizeof(SOCKET), 1);
	LOG(&info.sin_addr, sizeof(struct in_addr), 1);
	LOG(&port, sizeof(uint16_t), 1);
	LOG(len, sizeof(int), 1);
	LOG(flags, sizeof(int), 1);
	LOG(buf, sizeof(char), *len);
#else
	LOG("%s:%u, Len %d, Flags %d, socket %llu", inet_ntoa(info.sin_addr), port, *len, *flags, (unsigned long long)*s);
	LOGn("Data: ");  
	for(int i = 0; i < *len; i++) 
		LOGn("%02X ", (unsigned char)buf[i]);
	LOGn("\n");
#endif
	return;
}

inline void help_text()
{
	printf("What do you want to do?\n");
	printf("0. Disable logging\n");
	printf("1. Log send toggle\n");
	printf("2. Log recv toggle\n");
	printf("3. Log both toggle\n");
}

static inline void toggle_send()
{
	if(!plugin_id_send)
		plugin_id_send = register_handler(log_ws, WS_HANDLER_SEND, "A logging function for ws2_send");
	else
	{
		unregister_handler(plugin_id_send, WS_HANDLER_SEND);
		plugin_id_send = 0;
	}
}

static inline void toggle_recv()
{
	if(!plugin_id_recv)
		plugin_id_recv = register_handler(log_ws, WS_HANDLER_RECV, "A logging function for ws2_recv");			
	else
	{
		unregister_handler(plugin_id_recv, WS_HANDLER_RECV);
		plugin_id_recv = 0;
	}
}

static DWORD WINAPI console_handler(LPVOID param)
{
	int choice = 0;
	while(1)
	{
		help_text();
		printf("Current value: %d", choice);
		scanf("%d", &choice);
		if(!choice)
		{
			unregister_handler(plugin_id_send, WS_HANDLER_SEND);
			unregister_handler(plugin_id_recv, WS_HANDLER_RECV);
			plugin_id_send = 0;
			plugin_id_recv = 0;
			continue;
		}
		if(choice & 0x1) toggle_send();
		if(choice & 0x2) toggle_recv();
	}
	return 0;
}

static DWORD WINAPI setup_console(LPVOID param)
{
#if LOGGING == 1
	char name[64];
	sprintf(name,"log_%llu.bin",(unsigned long long)time(NULL));
	logfile = fopen(name,"wb");
#endif
	AllocConsole();
	freopen("CONOUT$","w",stdout);
	freopen("CONIN$","r",stdin);
	CreateThread(NULL,0,console_handler,NULL,0,NULL);
	while(1)
	{
		MSG msg;
		if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) 
		{
			if(msg.message == WM_QUIT)
			{
				FreeConsole();		
#if LOGGING == 1
				fclose(logfile);
#endif
				return msg.wParam;
			}
		}
	}
#if LOGGING == 1
	fclose(logfile);
#endif
	return 0;
}
