# Qbot-CobaltStrike-Config
A python script to decrypt possible Qbot-CobaltStrike  shellcode loader module. 

The script depends on Capstone to find addresses and keys.

usage below:

```console
Qbot-CobaltStrike-Config/qbot-cobalt.py" -file 39A5B05AEFB76C9EAB19C7F282B63CBC1C3343BA7BEB7D5DE57CBF8AAF474E80 

[+] Encrypted shellcode address found at --->  0x813338
[+] Key index  --->  0x7f
[+] Key  address found at --->  0x813680
[+] Shellcode size --->  0x343
{
  "C2_Address": "1.1.1.1",
  "User_Agent": "User-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko\r",
  "HTTP_Profile": "Referer: http://Malleable.cobaltstrike.com/\r",
  "HTTP_URI": "/somequery-0.0.0.big.max.js"
}
```