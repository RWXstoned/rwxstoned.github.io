---
title: Introducing GimmeShelter.py
subtitle: a situational awareness Python script to help you find where to put your beacons
thumbnail-img: "https://rwxstoned.github.io/assets/img/4/gimme-shelter.png"
---

[GimmeShelter.py](https://github.com/RWXstoned/GimmeShelter) is a lightweight Python script which will help you get a good view of what a Windows environment looks like, and highlight opportunities for hiding/running malware from unusual modules, or memory setups. 

![](https://rwxstoned.github.io/assets/img/4/gimme-shelter.png)

## Situational Awareness

Once on a host, a key thing in any red team operation is to become aware of what the "normal" activity on that environment looks like, ideally, very quickly. There is no rocket science here, we are talking about basic things such as the usual browser, which desktop apps connect to the internet, do any of the common apps have weird memory patterns with RWX sections, or odd DLL modules loaded from custom locations ?

Armed with that knowledge it becomes easier to blend in, once you know where to plant a persistency mechanism, or how to execute code, with an much better opsec than if randomly running payloads irrespective of the particularities of the environment.

This is exactly what this script does. It is in Python, which is ubiquitous and rarely suspicious. It is not too intrusive, merely looking around at processes. Do note, though, that it does perform a few API calls (using `ctypes`) to check memory pages settings in order to find RWX ones.

This is NOT a privesc tool, so it is not checking for processes running as `SYSTEM`, or for read/write permissions on DLLs (this would mean being much noisier). It is also NOT a memory scanner like [Moneta](https://github.com/forrest-orr/moneta). Should you wish to investigate a specific process or module further, you are encouraged to do so in a lab environment. The SHA256 are displayed so that you can ensure you get the same exact version of the executables or modules that you have identified as being of interest.

## What it is looking for

`GimmeShelter.py` will highlight the following potentially interesting properties for the processes currently running under the current user's context:

- is the process a dotNET process ? These are known to have more anomalous memory setups than other processes. By default, these are not displayed.
- does the process have "odd" modules loaded, from unusual directories ? This may open up DLL hijacking/sideloading possibilities.
- does the process have `wininet.dll` or `winhttp.dll` already loaded ? This is obviously a big opsec advantage for a process like that to shelter a beacon, as it will save it from loading those libraries...
- is the process signed ? Important: the checks performed by the script are not thorough, the signature validity is not checked. 
- does it have Control Flow Guard ? If yes, this has implications if trying to inject and run code into it.
- does the process have `RWX` private memory pages ? If so, this type of memory setup may fool detection mechanisms since this is "normal" behavior for that process to produce that type of indicators.
- does the process have `RWX` sections ? Similar to the above.

All these indicators should help you identify where and how to set up your loaders and beacons. The SHA256 of the process is displayed so that you can identify the exact version of that executable and ideallyreview it further in a lab, with tools like [Moneta](https://github.com/forrest-orr/moneta) which will give you a deeper view of the memory setup of that executable.

## Usage

```
usage: .\GimmeShelter.py [options]

options:
  -h, --help      show this help message and exit
  -v, --verbose   Show details on odd modules and RWX sections found

Filtering:
  -d, --dotnet    Display DotNet processes
  -s, --signed    Only show signed processes. WARNING: the validity of signature is NOT checked by this script
  -n, --net-only  Only show processes with winhttp or wininet already loaded
```

## Example Output

```
-------------------
RuntimeBroker.exe       [8224]
  [C:\Windows\System32\RuntimeBroker.exe]
  Sha256: 579dfced8f02a7e1e6e8df10c400117d3127ead7231776a1e467eb507261e920
-------------------
                 (!) Signed
                 (!) has loaded winhttp.dll


-------------------
Code.exe        [13648]
  [C:\Users\mickjagger\AppData\Local\Programs\Microsoft VS Code\Code.exe]
  Sha256: 292e6e6c7d9db5889c170cc71245ced1e8843599673a973841b7d47aa151efb6
-------------------
                 (!) Signed
                 (!) has loaded winhttp.dll


         ==== [ Unusual Modules ] ====

                 c:\users\mickjagger\appdata\local\programs\microsoft vs code\ffmpeg.dll
                         f903f4752f23ad88b08638b8d85c09fc2f1b17084ec655dac89aa559c17387a5

         ==== [ Private memory pages with RWX ] ====

                 ---> 0x18e335201000    49152 bytes
                 ---> 0x18e335221000    24576 bytes
                 ---> 0x18e335243000    102400 bytes
                 ---> 0x7ff6de900000    5505024 bytes

-------------------
firefox.exe     [1248]
  [C:\Program Files\Mozilla Firefox\firefox.exe]
  Sha256: 6835705aad4472891a216ab9ae3a6a7805a27310cdaa0614763b21d352d0a624
-------------------
                 (!) Signed


         ==== [ Unusual Modules ] ====

                 c:\program files\mozilla firefox\lgpllibs.dll
                         1c9c617f13feac3e94a6311eae20997f944da41bebca124002322ac6863d67e8
                 c:\program files\mozilla firefox\xul.dll
                         fa43976fbbbeca97f1116aaf26241daccacf0c29466f17b692d3cf4ee404f1e2
                 c:\program files\mozilla firefox\gkcodecs.dll
                         188f2d44534f978cb28d60e1118e287499adb2f19b0c36929f5badb7c1f94dfd
                 c:\program files\mozilla firefox\nss3.dll
                         8c121892b1bd1a964f194188685ea5d0e057b7d2bf9f9bc328ab5e005518c64d
                 c:\program files\mozilla firefox\freebl3.dll
                         c06ba1a174b47e01cbba84f88d1d66429b6bbda22e389bf579598c24ea2b06d8
                 c:\program files\mozilla firefox\mozglue.dll
                         292e38bd831a5d8948936748f48b1d47cfe49999514e95f5e9b165ef80f1203e
                 c:\program files\mozilla firefox\softokn3.dll
                         3dfa45616bcd5fe594b0dd39acf7f5216f8a3816cee188ef672ff8d44e53a2b8

         ==== [ Private memory pages with RWX ] ====

                 ---> 0x1bfd47b1000     65536 bytes
                 ---> 0x1bfd48b1000     65536 bytes
                 ---> 0x1bfd48d1000     131072 bytes
```

