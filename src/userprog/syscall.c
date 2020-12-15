#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include <string.h>
#include "process.h"
#define MAXCALL 21
#define MAXFiles 200
#define STDIN 0
#define STDOUT 1
static void syscall_handler (struct intr_frame *);

void sys_halt(struct intr_frame* f); /* Halt the operating system. */
void sys_exit(struct intr_frame* f); /* Terminate this process. */
void sys_exec(struct intr_frame* f); /* Start another process. */
void sys_wait(struct intr_frame* f); /* Wait for a child process to die. */
void sys_create(struct intr_frame* f); /* Create a file. */
void sys_remove(struct intr_frame* f);/* Create a file. */
void sys_open(struct intr_frame* f); /*Open a file. */
void sys_filesize(struct intr_frame* f);/* Obtain a file's size. */
void sys_read(struct intr_frame* f);  /* Read from a file. */
void sys_write(struct intr_frame* f); /* Write to a file. */
void sys_seek(struct intr_frame* f); /* Change position in a file. */
void sys_tell(struct intr_frame* f); /* Report current position in a file. */
void sys_close(struct intr_frame* f); /* Close a file. */
static void (*syscall_handlers[MAXCALL]) (struct intr_frame *);

struct file_node{
  int fd;
  struct file *f;
  struct list_elem elem;
  struct list_elem thread_elem;
};

struct file_node *getFile(struct thread *t,int fd);

static struct list file_list;
struct lock file_lock;
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_handlers[SYS_HALT]=&sys_halt;
  syscall_handlers[SYS_EXIT]=&sys_exit;
  syscall_handlers[SYS_WAIT]=&sys_wait;
  syscall_handlers[SYS_CREATE]=&sys_create;
  syscall_handlers[SYS_REMOVE]=&sys_remove;
  syscall_handlers[SYS_OPEN]=&sys_open;
  syscall_handlers[SYS_WRITE]=&sys_write;
  syscall_handlers[SYS_SEEK]=&sys_seek;
  syscall_handlers[SYS_TELL]=&sys_tell;
  syscall_handlers[SYS_CLOSE]=&sys_close;
  syscall_handlers[SYS_READ]=&sys_read;
  syscall_handlers[SYS_EXEC]=&sys_exec;
  syscall_handlers[SYS_FILESIZE]=&sys_filesize;

  list_init(&file_list);
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if(!is_user_vaddr(f->esp)){
    exit(-1);
  }
  int syscalll_num= *((int *)(f->esp));
  
  syscall_handlers[syscalll_num](f);
}

int write(int fd,char *buffer,unsigned size){
  
  if(fd==1){
    putbuf( buffer,size);
    return (int)size;
  }else{
    struct thread *cur =thread_current();
    struct file_node *fn=getFile(cur,fd);
    if(fn==NULL){
      return 0;
    }
    return (int) file_write(fn->f,buffer,size);
  }
}

void sys_write(struct intr_frame* f){
  int *esp =(int *)f->esp;
  if(!is_user_vaddr(esp+7)){
    exit(-1);
  }
  int fd = *(esp+1);
  char *buffer = (char*)*(esp+6);
  unsigned size = *(esp+3);
  f->eax=write(fd,buffer,size);
}

void exit(int status){
  struct thread *t;
  t=thread_current();
  t->ret=status;
  thread_exit();
}

void sys_exit(struct intr_frame* f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    exit(-1);
  }
  int ret = *((int *)f->esp+1);
  exit(ret);
}

void sys_wait(struct intr_frame* f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    exit(-1);
  }
  tid_t tid=*((int *)f->esp+1);
  if(tid!=-1){
    f->eax=process_wait(tid);
  }else {
    f->eax=-1;
  }
}

void sys_halt(struct intr_frame* f){
  shutdown_power_off();
  f->eax=0;
}

void sys_create(struct intr_frame* f){
  if(!is_user_vaddr(((int *)f->esp)+6)){
    exit(-1);
  }
  if((const char*)*((unsigned int *)f->esp+4)==NULL){
    f->eax=-1;
    exit(-1);
  }
  bool ret=filesys_create((const char *)*((unsigned int *)f->esp+4),*((unsigned int *)f->esp+5));
  f->eax=ret;
}

void sys_remove(struct intr_frame* f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    exit(-1);
  }
  char *fl=(char*)*((int *)f->esp+1);
  f->eax=filesys_remove(fl);
}

void sys_open(struct intr_frame* f){
  if(!is_user_vaddr(((int *)f->esp)+6)){
    exit(-1);
  }
  struct thread *cur=thread_current();
  const char *FileName =(char*)*((int *)f->esp+1);
  if(FileName==NULL){
    f->eax=-1;
    exit(-1);
  }
  struct file_node *fn =(struct file_node *)malloc(sizeof(struct file_node));
  fn->f=filesys_open(FileName);
  if(fn->f==NULL||cur->FileNum>=MAXFiles){
    fn->fd=-1;
  }else
  {
    (cur->maxfd)++;
    fn->fd=cur->maxfd;
  }
  f->eax=fn->fd;
  if(fn->fd==-1){
    free(fn);
  }else{
    cur->FileNum++;
    list_push_back(&cur->file_list,&fn->elem);
  }
}

void seek(int fd,unsigned pos){
  struct file_node *fn=getFile(thread_current(),fd);
  if(fn==NULL){
    exit(-1);
  }
  file_seek(fn->f,pos);
}

void sys_seek(struct intr_frame* f){
  if(!is_user_vaddr(((int *)f->esp)+6)){
    exit(-1);
  }
  int fd=*((int *)f->esp+4);
  unsigned pos = *((unsigned *)f->esp+5);
  seek(fd,pos);
}

int tell(int fd){
  struct file_node *fn =getFile(thread_current(),fd);
  if(fn==NULL||fn->f==NULL){
    exit(-1);
  }
  return file_tell(fn->f);
}

void sys_tell(struct intr_frame* f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    exit(-1);
  }
  int fd=*((int *)f->esp+1);
  f->eax=tell(fd);
}

void close(struct thread *t,int fd){
  struct list_elem *e,*p;
  struct file_node *fn;
  for(e=list_begin(&t->file_list);e!=list_end(&t->file_list);e=list_next(e)){
    fn=list_entry(e,struct file_node,elem);
    if(fn->fd==fd){
      list_remove(e);
      if(fd==t->maxfd){
        t->maxfd--;
      }
      t->FileNum--;
      file_close(fn->f);
      free(fn);
      return ;
    }
  }
  exit(-1);
}

void ThreadFileclose(struct thread *t){
  struct list_elem *e;
  while(!list_empty(&t->file_list)){
    e=list_pop_front(&t->file_list);
    struct file_node *fn=list_entry(e,struct file_node,elem);
    file_close(fn->f);
    free(fn);
  }
  t->FileNum=0;
}

void sys_close(struct intr_frame* f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    exit(-1);
  }
  struct thread *cur=thread_current();
  int fd =*((int *)f->esp+1);
  close(cur,fd);
}

int read(int fd,char *buffer,unsigned size){
  struct thread* cur=thread_current();
  struct file_node *fn =NULL;
  unsigned int i;
  if(fd==STDIN_FILENO){
    for ( i = 0; i < size; i++)
    {
      buffer[i]=input_getc();
    }
    return size;
  }else{
    fn=getFile(cur,fd);
    if(fn==NULL){
      return -1;
    }
    return file_read(fn->f,buffer,size);
  }
}

void sys_read(struct intr_frame* f){
  int *esp=(int *)f->esp;
  if(!is_user_vaddr(esp+7)){
    exit(-1);
  }
  int fd=*(esp+1);
  char *buffer=(char*)*(esp+6);
  unsigned size=*(esp+3);
  if(buffer==NULL||!is_user_vaddr(buffer+size)){
    f->eax=-1;
    exit(-1);
  }
  f->eax=read(fd,buffer,size);
}

tid_t exec(const char * file){
  tid_t tid=-1;
  char *newfile=(char *)malloc(sizeof(char)*(strlen(file)+1));
  memcpy(newfile,file,strlen(file)+1);
  tid=process_execute(newfile);
  struct thread *t =GetThreadFromTid(tid);
  sema_down(&t->ExecSema);
  free(newfile);
  return t->tid;
}

void sys_exec(struct intr_frame* f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    exit(-1);
  }
  const char *file_name=(char*)*((int *)f->esp+1);
  if(file_name==NULL){
    f->eax=-1;
    return ;
  }
  f->eax=exec(file_name);
}

int filesize(int fd){
  struct thread *cur=thread_current();
  struct file_node *fn=getFile(cur,fd);
  if(fn==NULL){
    return -1;
  }
  return file_length(fn->f);
}

void sys_filesize(struct intr_frame* f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    exit(-1);
  }
  int fd=*((int *)f->esp+1);
  f->eax=filesize(fd);
}

struct file_node *getFile(struct thread *t,int fd){
  struct list_elem *e;
  for(e=list_begin(&t->file_list);e!=list_end(&t->file_list);e=list_next(e)){
    struct file_node *fn=list_entry(e,struct file_node,elem);
    if(fn->fd==fd){
      return fn;
    }
  }
  return NULL;
}