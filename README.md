# VirusTotal Lookup Utility
This is a command line utility designed to submit files and retrieve reports from [VirusTotal](https://www.virustotal.com)'s WebAPI.

*Normal mode*
![](screenshots/demo1.png?raw=true)

*Verbose mode*
![](screenshots/demo2.png?raw=true)

*Verbose mode - clean results*
![](screenshots/demo3.png?raw=true)

## Usage
The utility relies on a VirusTotal API key to function. You must create a VirusTotal account in order to receive an API key.
The API key can be fed to the utility in one of two ways: either as a command line argument, or through a `.vtlookup-config.json` file which is automatically generated if no API key is supplied as a command line argument. The location of the file is defined by the `CONFIG_FILE_PATH` macro. On Windows, this defaults to `C:\.vtlookup-config.json` and on Unix `~/.vtlookup-config.json`. Ensure that you have sufficient privilages when the configuration file is generated for the first time.

The utility can be invoked using the following parameters
* `--api-key` | `-k` : One of two ways of providing an API key.
* `--verbose` | `-v` : Enables verbose output, displaying the full results in place of a summary.
* `--file` | `-f` : The path to a file, one of two ways of providing a resource.
* `--hash` | `-x` : A hash of the target resource, one of two ways of providing a resource.

## Building
The code depends on the Windows library in order to color-code the results, however the color change calls can easily be removed without having to modify existing code. In the future I will add a preprocessor directive for Windows/Unix that will use a different color changing function, but for now the dependency can easily be removed if you wish to compile for a non-Windows platform.

QMake is the official build system of this project, and a Qt project file is included. However building it manually isn't much of a problem. This project depends on LibCurl and OpenSSL. The paths to the include directories of both libraries must be passed to your compiler of choice. 

The specific dependencies of LibCurl depends on how it was built. The pre-compiled version for Windows is linked with a version of LibCurl that uses the Windows SSPI library to handle cryptography. Depending on how yours is built, you may depend on OpenSSL, LibSSH, or wolfSSL, etc. I suggest you follow the LibCurl build instructions for your platform rather than using pre-compiled versions, as pre-compiled versions vary too much in the way they are built.

The project was designed to be compiled in 64-bit mode, so I haven't tested a 32-bit build, so I cannot garuentee that a 32 bit build would work, but nothing should hinder it from working in theory, just make sure that OpenSSL and LibCurl's static libs are both built in 32-bit mode as well.

### OpenSSL dependencies.
* libssl.lib (Static)
* libcrypto.lib (Static)
* openssl.lib (Static)

### LibCurl dependencies.
* libcurl.lib (Static)
* ws2_32 .lib  (Windows Specific)
* wldap3.lib   (Windows Specific)
* advapi32.lib (Windows Specific)
* kernel32.lib (Windows Specific)
* comdlg32.lib (Windows Specific)
* crypt32.lib  (Windows Specific)
* normaliz.lib (Windows Specific)

## Example Invocations

*Normal mode*
```
λ vtlookup --file cain.exe

REPORT FOUND ~> 34 / 73 [ 47%] @ 2019-12-27 16:21:57 | 34 positives & 39 negatives, out of 73 distinct AV engine scans..
```

*Verbose mode*
```
λ vtlookup --file cain.exe --verbose

-----------------------------------------------------------------------------------------------------------------------------------------------------
ALYac(1.1.1.5)......................................................CLEAN | APEX(5.98)..........................................................CLEAN
AVG(18.4.3895.0).....................................FileRepMalware [PUP] | Acronis(1.1.1.58)...................................................CLEAN
Ad-Aware(3.0.5.370).................................................CLEAN | AegisLab(4.2).................................Riskware.Win32.CainAbel.1!c
AhnLab-V3(3.17.0.26111).............................................CLEAN | Alibaba(0.3.0.5)..........................HackTool:Win32/Generic.4141602c
Antiy-AVL(3.0.0.1).................................Trojan/Win32.TSGeneric | Arcabit(1.0.0.865)..................................................CLEAN
Avast(18.4.3895.0)..................................................CLEAN | Avast-Mobile(191219-00).............................................CLEAN
Avira(8.3.3.8)......................................................CLEAN | Baidu(1.0.0.2)......................................................CLEAN
BitDefender(7.2)....................................................CLEAN | BitDefenderTheta(7.2.37796.0).......................................CLEAN
Bkav(1.3.0.9899)....................................................CLEAN | CAT-QuickHeal(14.00)...........................Trojan.GenericPMF.S3027058
CMC(1.1.0.977)......................................................CLEAN | ClamAV(0.102.1.0)......................................Win.Tool.Mikey-897
Comodo(31893)...................................ApplicUnsaf@#b9b7krks6mnf | CrowdStrike(1.0)....................................................CLEAN
Cybereason(1.2.449)......................................malicious.8966c8 | Cylance(2.3.1.101).................................................Unsafe
Cyren(6.2.2.2)......................................................CLEAN | DrWeb(7.0.42.9300)..................................................CLEAN
ESET-NOD32(20577)..........a variant of Win32/CainAbel potentially unsafe | Emsisoft(2018.12.0.1641)............................................CLEAN
Endgame(3.0.15)...............................malicious (high confidence) | F-Prot(4.7.1.166)...................................................CLEAN
F-Secure(12.0.86.52)................................................CLEAN | FireEye(29.7.0.0).............................Generic.mg.80dfbab8966c8158
Fortinet(6.2.137.0).....................................Riskware/CainAbel | GData(A:25.24382B:26.17144)................Win32.Application.Agent.C3WP1F
Ikarus(0.1.5.2).......................................HackTool.Win32.Cain | Invincea(6.3.6.26157)...........................................heuristic
Jiangmin(16.0.100)..................................................CLEAN | K7AntiVirus(11.85.32911)...................Unwanted-Program ( 004d38111 )
K7GW(11.85.32911)..........................Unwanted-Program ( 004d38111 ) | Kaspersky(15.0.1.13)................................................CLEAN
Kingsoft(2013.8.14.323).............................................CLEAN | MAX(2019.9.16.1)....................................................CLEAN
Malwarebytes(2.1.1.1115)...................PUP.Optional.PasswordTool.Cain | MaxSecure(1.0.0.1)..........................Trojan.Malware.1747990.susgen
McAfee(6.0.6.653).......................................HackTool-CainAbel | McAfee-GW-Edition(v2017.3010)...........................HackTool-CainAbel
MicroWorld-eScan(14.0.297.0)........................................CLEAN | Microsoft(1.1.16600.7)................................HackTool:Win32/Cain
NANO-Antivirus(1.0.134.25031).......................................CLEAN | Paloalto(1.0).......................................................CLEAN
Panda(4.6.4.2)..........................................HackTool/CainAbel | Qihoo-360(1.0.0.1120)...............................................CLEAN
Rising(25.0.0.24)...................................................CLEAN | SUPERAntiSpyware(5.6.0.1032)........................................CLEAN
Sangfor(1.0)........................................................CLEAN | SentinelOne(1.12.1.57)..............................................CLEAN
Sophos(4.98.0)..........................................Cain n Abel (PUA) | Symantec(1.11.0.0)...............................................CainAbel
TACHYON(2019-12-27.02)..............................................CLEAN | Tencent(1.0.0.1)....................................................CLEAN
TotalDefense(37.1.62.1).............................................CLEAN | Trapmine(3.2.16.890)..............................suspicious.low.ml.score
TrendMicro(11.0.0.1006).........................................HKTL_CAIN | TrendMicro-HouseCall(10.0.0.1040)...............................HKTL_CAIN
VBA32(4.3.0)........................................................CLEAN | VIPRE(80342)......................................Trojan.Win32.Generic!BT
ViRobot(2014.3.20.0)...............................Adware.Agent.1374720.A | Webroot(1.0.0.403)..................................................CLEAN
Yandex(5.5.2.24).......................................Riskware.CainAbel! | Zillya(2.0.0.3986)...........................Adware.OutBrowse.Win32.80197
ZoneAlarm(1.0)......................................................CLEAN | Zoner(1.0.0.1)......................................................CLEAN
eGambit(NONE GIVEN)...................................Unsafe.AI_Score_71% |
-----------------------------------------------------------------------------------------------------------------------------------------------------

```
