/* Forks and waits for a single child process. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void) 
{
  int pid;

  if (pid = fork("child")){
    //msg("why not here");
    int status = wait (pid);
    msg ("Parent: child exit status is %d", status);
  } else {
    //msg("why not here22");
    msg ("child run");
    exit(81);
  }
}
