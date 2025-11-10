#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>

#include "plugins.h"
#include "list.h"

void load_plugins(LPCTSTR directory, struct WS_plugins *list)
{
    DIR *dir;
    struct dirent *ent;
    struct WS_plugins *t;

    if ((dir = opendir(directory)) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                continue;

            char fullpath[MAX_PATH];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", directory, ent->d_name);

            HMODULE h = LoadLibraryA(fullpath);
            if (h != NULL)
            {
                t = (struct WS_plugins *)malloc(sizeof(struct WS_plugins));
                if (t)
                {
                    t->plugin = h;
                    INIT_LIST_HEAD(&t->plugins);
                    list_add(&(t->plugins), &(list->plugins));
                }
            }
        }
        closedir(dir);
    }
}
