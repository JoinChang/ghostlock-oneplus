.section .rodata
.global embedded_wallpaper_start
.global embedded_wallpaper_end
.balign 16
embedded_wallpaper_start:
.incbin "assets/wallpaper.webp"
embedded_wallpaper_end:
.balign 16
