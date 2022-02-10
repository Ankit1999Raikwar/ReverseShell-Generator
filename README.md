# ReverseShell-Generator

### Reverse shell Genrator v1

## List of payload 

`bash-i ,bash-udp (udp port),bash5 ,bash-196,bash-r (readline) ,zsh (linux zsh terminal)`

`nc-e ,nc-c ,ncat-e ,ncat.exe-e ,ncat-udp ,nc-mknod ,nc-mkfifo ,nc-pipe,nc.exe-w (Windows)`

`php,php-cmd ${red}(web cmd execution)${noc} ,php-system ,php-passthru ,php-exec ,php-shell_exec ,php-proc_open ,php-poopen ,php-'`

`python-1 ,python-2 ,python3-1 ,python3-2 ,python-s(forshort)`

`ruby ,ruby-sh ,ruby-w (Windows),c-win(Windows)`

`perl ,perl-sh ,perl-w (Windows)`

`java1 ,java2 ,java3`

`Lua-1 ,Lua-2`

`socat-1 ,socat-tty`

`telnet-mkfifo ,telnet`

`(Windows): powershell-cmd2 ,powershell-cmd2 ,powershell-cmd3 ,powershell-cmd4 ,powershell-tls ,Windows-pty`

`golang ,dart ,Groovy,awk ,node.js,tcl-sh,xterm ,haskell1,haskell2(long version) ,rustcat,c-lang(normal c language)`

### Metasploit payload 

`asp ,jsp ,lin-bin/linux(elf) ,lin-bin-s/linux-s(stager) ,osx-bin/Mac ,war`

`win-bin(exe),win-bin(exe)-s,shellcode`

`php-m(meterpreter rev),php-revm(normal php rev shell)`

`android,python,bash`

### Some other useful payload

`pentest-monkey`

`php-lvan-sincek`

## For intractive shell

`python -c 'import pty;pty.spawn("/bin/bash")'`
`Ctrl+z`
`stty raw -echo;fg`
`export TERM=xterm`

