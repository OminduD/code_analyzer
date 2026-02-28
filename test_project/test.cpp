// test.cpp
#include <iostream>
#include <string.h>

int main() {
  char dest[50];
  char src[] = "very bad code";

  // VULNERABILITY CPP001
  strcpy(dest, src);

  // VULNERABILITY CPP002
  system("echo execution!");

  return 0;
}
