.section .rodata
.balign 16

.global embedded_su_start
.type embedded_su_start, %object
embedded_su_start:
.incbin "build/embed/su_daemon_aarch64_pie"

.global embedded_su_end
.type embedded_su_end, %object
embedded_su_end:
.byte 0
