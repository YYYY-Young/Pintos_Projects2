#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <threads/thread.h>
void syscall_init (void);

void exit(int status);
void ThreadFileclose(struct thread *t);


#endif /* userprog/syscall.h */
