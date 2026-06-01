#pragma once
char *w32_basename(char *path);
#define basename w32_basename
char *dirname(char *path);
