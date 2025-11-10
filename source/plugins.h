#ifndef PLUGINS_H
#define PLUGINS_H

#include <windows.h>
#include "list.h"

struct WS_plugins {
    struct list_head plugins;
    HMODULE plugin;
};

void load_plugins(LPCTSTR directory, struct WS_plugins *list);

#endif // PLUGINS_H
