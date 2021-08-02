[bits 32]

%define SYS_WRITE 1
%define SYS_EXIT 60

%define STD_OUT 1

global _start

section .text
_start:
  mov al, SYS_WRITE
  mov edi, STD_OUT
  mov esi, message
  
  push message
  call strlen
  ; write(STD_OUT, message, message_length)
  syscall
  
  mov eax, SYS_EXIT
  mov edi, 68
  jmp label
  add edi, 200
label:
  ; exit(edi)
  syscall
  ret

; argument on stack, result in edx
strlen:
  mov ecx, [esp + 4]
  xor edx, edx

strlen_loop:
  mov bl, [ecx + edx]
  cmp bl, 0x0
  je strlen_end
  add edx, 1
  jmp strlen_loop

strlen_end:
  ret

; end marker
ud0

section .data
  message: db "Hello, World!", 10, 0
  message_length: db $ - message