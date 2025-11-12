# Hello-World
Test
One



Introduction
$a = 0
$new = (Get-Content -Path "new.txt")
$old = (Get-Content -Path "old.txt")
foreach ($line in get-content -Path "new.txt"){
if ($new[$a] -eq $old[$a]) {"$a"};
$a++;}

---
$az = 0
$at = 0
$wordstxt = (Get-Content -Path "words.txt")
foreach ($line in $wordstxt){
if ($line | Select-String -Pattern "a"){$az++}
elseif ($line | Select-String -Pattern "z"){$az++}
$at++
}

---
for ($i = 999; $i -ge 1; $i--){
Expand-Archive -Path $("Omega"+$i+"\Omega*") -DestinationPath $("Omega"+ ($i-1)) -Force
}

---
$cc = 0; $at=0
foreach ($line in $wordstxt){
if ($line | Select-String -Pattern "aaa"){$cc++}
elseif ($line | Select-String -Pattern "aab"){$cc++}
elseif ($line | Select-String -Pattern "aac"){$cc++}
elseif ($line | Select-String -Pattern "aad"){$cc++}
elseif ($line | Select-String -Pattern "aae"){$cc++}
elseif ($line | Select-String -Pattern "aaf"){$cc++}
elseif ($line | Select-String -Pattern "aag"){$cc++}
$at++
}

---
Get-ChildItem -Recurse -Force | ForEach-Object{
Get-Item $_.FullName -Stream *
} | Where-Object Stream -ne ':$DATA'

---
Get-ChildItem -Path "C:\Users\..." -Hidden -File -Recurse 

---
Get-ChildItem -Recurse -Force | ForEach-Object{
Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue
} | Where-Object Stream -ne ':$DATA'

---
Get-ChildItem -Recurse -Force -File | ForEach-Object{
Get-Content $_.FullName | Select-String -Pattern "fortune" 
} 

---
Get-ChildItem -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object{
$_.FullName | Select-String -Pattern "cookie"
}

---
Get-ChildItem
Get-Content
Get-Item
Get-Help
bcdedit
Sysinternal
	TCPView
	Autoruns
	AccessChk



---
$hd = ls
for lines in $hd
do ls -l $(lines);
done

---
find /home -type f -name ".profile" -size +807

---
iterm=$(cat numbers | grep -v '..-..-..-..-..-..' | grep -E '(^[0-
9]|^[0-9][0-9]|^[0-9][0-9][0-9])\.([0-9]|[0-9][0-9]|[0-9][0-9][0-9])\.([0-9]|[0-9][
0-9]|[0-9][0-9][0-9])\.([0-9]|[0-9][0-9]|[0-9][0-9][0-9])$')

---
iterm=$(cat numbers | grep -v '..-..-..-..-..-..' | grep -E '(^[0-
9]|^[0-9][0-9]|^[1-2][0-9][0-9])\.([0-9]|[0-9][0-9]|[1-2][0-9][0-9])\.([0-9]|[0-9][
0-9]|[1-2][0-9][0-9])\.([0-9]|[0-9][0-9]|[1-2][0-9][0-9])$')
And then count numbers below 255

---
cat numbers | grep -e '..-..-..-..-..-..'| grep '^.\{1,17\}$' | wc -l

---
awk 'NR==420, NR==1337 {print $0}' numbers | sha512sum

---
awk -F'\t' '{print $1"," $2"," $3"," $4"," $5"," $6}' connections_m  | md5sum

---
 for line in $cmds; do awk '$line==$1 {print $3}'; done awk '$1=="badge" {print $3}' paths

---
cat numbers | grep -e '..-..-..-..-..-..'| grep '^.\{1,17\}$' | grep -E '(^[0-9][02468]|^[0-9][ACE]|^[A-F][02468]|^[A-F][ACE])-([0-9][0-9]|[0-9][A-F]|[A-F][0-9]|[A-F][A-F])-([0-9][0-9]|[0-9][A-F]|[A-F][0-9]|[A-F][A-F])-([0-9][0-9]|[0-9][A-F]|[A-F][0-9]|[A-F][A-F])-([0-9][0-9]|[0-9][A-F]|[A-F][0-9]|[A-F][A-F])-([0-9][0-9]|[0-9][A-F]|[A-F][0-9]|[A-F][A-F])$' |wc -l

---
guards=$(getent group guardsmen | awk -F ',' '{ for(i=1; i<=NF; i++) print $i}')

---
qemu-system-x86_64 -device usb-ehci -smp 2 -m 2G -net none Win_Bootkit.vdi

---
dd bs=1 if=mbroken count=16 skip=446 | xxd -l 512 -c 0x10 -g 1
dd bs=1 if=mbroken count=16 skip=446 | md5sum

---
Get-ChildItem -Recurse -Force -Directory -ErrorAction SilentlyContinue | ForEach-Object{
$_.FullName | Select-String -Pattern "Chrome"
}
Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Chrome*"} |Select-Object FullName
Get-ChildItem -Path "C:\Users" -Filter "History" -Recurse -Force -ErrorAction SilentlyContinue |select FullName |Select-String -Pattern "Chrome"
C:\Users\...\Downloads\strings.exe C:\Users\student\AppData\Local\Google\Chrome\'user data'\Default\History -accepteula

---
Get-ChildItem -Recurse -Force C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction Continue | select Name, LastAccessTime 
Get-ChildItem -Recurse -Force C:\Users\student -ErrorAction SilentlyContinue | where-object {-not $_.PSIsContainer} | Sort-Object LastAccessTime -Descending | select-object -First 10 FullName, LastAccessTime | ft -wrap
[System.Text.Encoding]::Unicode.GetString((gp "Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt")."6")

---
Get-ChildItem 'C:\$RECYCLE.BIN' -Recurse -Force -File -ErrorAction SilentlyContinue| ForEach-Object{
if ((Get-Content $_.FullName | Select-String -Pattern "Dont" ) -eq "DontTrashMeyo") { Get-Item $_.FullName}
} 
DontTrashMeyo
Get-ChildItem 'C:\$RECYCLE.BIN' -Recurse -Force -File -ErrorAction SilentlyContinue| ForEach-Object{
findstr /m "Dont" $_.FullName 
} 

---
 [System.Text.Encoding]::Unicode.GetString((gp "Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.ps1")."MRUListEx")
 C:\Users\...\Downloads\strings.exe -accepteula 'C:\Users\student\AppData\Roaming\Microsoft\Windows\recent\The Internet.lnk'
 
---
 xpath -q -e '//address/@addr' output.xml | md5sum
xpath -q -e '//address/@addr | //port/@portid' output.xml |md5sum

---
jq '."id.orig_h"' conn.log |sort |uniq | wc -l

---
 xpath -q -e '//host[ports/port/state/@state="open"]/ports/port/@portid | //host[ports/port/state/@state="open"]/address/@addr' output.xml |md5sum
 
---
C:\Users\...\Desktop\Memory_Analysis\volatility_2.6_win64_standalone.exe

 
 ---
 Get-ADUser -Filter 'Name -like "*"'  -Properties * | select telephonenumber, DistinguishedName |Select-String -Pattern 336 
