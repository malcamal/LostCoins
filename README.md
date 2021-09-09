# LostCoins v3.0
 - This is a modified version [VanitySearch](https://github.com/JeanLucPons/VanitySearch/). 
Huge thanks [kanhavishva](https://github.com/kanhavishva) and to all developers whose codes were used in LostCoins.
## Quick start
- Сonvert addresses into binary hashes RIPEMD160 use [b58dec.exe](https://github.com/phrutis/LostCoins/blob/main/Others/b58dec.exe) Сommand: ```b58dec.exe 1.txt 2.bin```
- It is important to sort the 2.bin file otherwise the Bloom search filter will not work as expected.
- To sort 2.bin use the program [RMD160-Sort.exe](https://github.com/phrutis/LostCoins/blob/main/Others/RMD160-Sort.exe) Сommand: ```RMD160-Sort.exe 2.bin addresse160-Sort.bin``` 
- The minimum number of hashes160 in addresse160-Sort.bin must be at least 1000
- For Multi GPUs use ```LostCoins.exe -t 0 --gpu --gpui 0,1 -f test.bin -r 2 -n 64 -m 250```  
- Grid auto for weak cards example ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 2 -n 64 -m 99```
- My RTX2070 in auto: -x 256,128 I added ```LostCoins.exe -t 0 -g -i 0 -x 288,512``` the speed has doubled.
- Do not use the GPU+CPU will drop the speed. Run 2 copies of the program one on the CPU and the second on the GPU
- You can search hashes160 of other coins, if it finds it, it will give an empty legacy address 1.. and positive private key and hex160
## In the project implementation
- Built-in [maskprocessor](https://github.com/hashcat/maskprocessor) mode for searching passphrases on GPU
- Search with [mnemonics bip39](https://github.com/libbitcoin/libbitcoin-system)
- If you are a programmer and can help implement these modes, this is welcome.  

## Parametrs:
```
C:\Users\user>LostCoins.exe -h
Usage: LostCoins [options...]
Options:
    -v, --version          Print version. For help visit https://github.com/phrutis/LostCoins
    -c, --check            Check the working of the code LostCoins
    -u, --uncomp           Search only Uncompressed addresses
    -b, --both             Search both (Uncompressed and Compressed addresses)
    -g, --gpu              Enable GPU calculation
    -i, --gpui             GPU ids: 0,1...: List of GPU(s) to use, default is 0
    -x, --gpux             GPU gridsize: g0x,g0y,g1x,g1y, ...: Specify GPU(s) kernel gridsize, default is 8*(MP number),128
    -t, --thread           ThreadNumber: Specify number of CPUs thread, default is number of core
    -o, --out              Outputfile: Output results to the specified file, default: Found.txt
    -m, --max              Number 1-10000 For GPU Reloads random started hashes every billions in counter. Default: 100 billion
    -s, --seed             PassPhrase   (Start bit range)
    -z, --zez              PassPhrase 2 (End bit range)
    -r, --rkey             Number of random modes
    -n, --nbit             Number of letters and number bit range 1-256
    -f, --file             RIPEMD160 binary hash file path
    -d, --diz              Display modes -d 0 [info+count], -d 1 SLOW speed [info+hex+count], Default -d 2 [count] HIGH speed
    -k, --color            Colors: 1-255 Recommended 3, 10, 11, 14, 15, 240 (White-black)
    -h, --help             Shows this page
 ```
 
###  Search Passphrases 
- [**Use old databases or Generator to search for passphrases**](https://github.com/phrutis/LostCoins/blob/main/Others/Modes.md) 
## Mode 0 
## Find Passphrases and Privat keys from a text file
### Passphrases from a file
 - To search for passphrases, use mode **-u** or **-b** for old Lost Coins 
 - Each passphrase on a new line. 
 - For CPU (NORMAL) ```LostCoins.exe -t 11 -f test.bin -r 0 -s Passphrases.txt -d 3``` 
 - For CPU (SLOW) ```LostCoins.exe -t 11 -f test.bin -r 0 -s Passphrases.txt -d 0```
 - For CPU (Very SLOW)  ```LostCoins.exe -t 11 -f test.bin -r 0 -s Passphrases.txt -d 1```
```
C:\Users\user>LostCoins.exe -b -t 11 -f test.bin -r 0 -s test.txt -d 3

 LostCoins v3.0

 SEARCH MODE  : COMPRESSED & UNCOMPRESSED
 DEVICE       : CPU
 CPU THREAD   : 11
 GPU IDS      : 0
 GPU GRIDSIZE : -1x128
 RANDOM MODE  : 0
 ROTOR SPEED  : HIGH (only counter)
 CHARACTERS   : 0
 PASSPHRASE   : test.txt
 PASSPHRASE 2 :
 DISPLAY MODE : 3
 TEXT COLOR   : 15
 GPU REKEY    : 100000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 000001E9091CC040
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Thu Sep  9 19:26:21 2021

  Random mode : 0
  Rotor       : Loading passphrases from file test.txt ...
  Loaded      : 15671044 passphrases
  Rotor       : For large files use -t 11 max (1 core = ~30.000/s, 1 thread = ~5.000/s)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  [00:00:18] [CPU: 140,89 Kk/s] [T: 2,399,115] [F: 0]
  =================================================================================
  * PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x                                *
  * Priv(WIF) : p2pkh:L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm        *
  * Priv(HEX) : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  *
  =================================================================================
  [00:00:35] [CPU: 193,92 Kk/s] [T: 5,614,019] [F: 1]
  =================================================================================
  * PubAddress: 1FFtUDpR2CYZDc9TxzNpbNP1U6cXQ9Lq5c                                *
  * Priv(WIF) : p2pkh:5J9J63iW7s5p54T569qstediqNgBTLXpUmxUtQwsXTaHz3JCsKt        *
  * Priv(HEX) : 2B2961A431B23C9007EFE270C1D7EB79C19D4192D7CD2D924176EB0B19E7D2A1  *
  =================================================================================
  [00:01:13] [CPU: 188,31 Kk/s] [T: 12,382,627] [F: 2]
  =================================================================================
  * PubAddress: 19JxMTT1YqVHAx16NdvgULNajRYvrbFjm1                                *
  * Priv(WIF) : p2pkh:5HwfeuhdFscL9YTQCLT2952dieZEtKbzJ328b4CR1v6YUVLu2D7        *
  * Priv(HEX) : 10C22BCF4C768B515BE4E94BCAFC71BF3E8FB5F70B2584BCC8C7533217F2E7F9  *
  =================================================================================
  [00:01:35] [CPU: 179,42 Kk/s] [T: 16,441,171] [F: 3]
  =================================================================================
  * PubAddress: 15KqNGHFEViRS4WTYYJ4TRoDtSXH5ESzW9                                *
  * Priv(WIF) : p2pkh:L3BEabkqcsppnTdzAWiizPEuf3Rvr8QEac21uRVsYb9hjesWBxuF        *
  * Priv(HEX) : B1C02B717C94BD4243E83B5E98BA37FB273BC035E4AD8FC438EA4D07A1043F56  *
  =================================================================================


BYE
```
### Privat keys from a file
 - For CPU (NORMAL) ```LostCoins.exe -t 11 -f test.bin -r 0 -s private-keys.txt -z keys -d 3``` 
 - For CPU (SLOW) ```LostCoins.exe -t 11 -f test.bin -r 0 -s private-keys.txt -z keys -d 0```
 - For CPU (Very SLOW)  ```LostCoins.exe -t 11 -f test.bin -r 0 -s private-keys.txt -z keys -d 1```
 - Private key (HEX) looks like this only numbers 0-9 and letters a,b,c,d,e,f on a new line. 
 - Example: 4A70FE9AA6436E02C2DEA340FBD1E352E4EF2D8CE6CA52AD25D4B95471FC8BF2
```
C:\Users\user>LostCoins.exe -t 11 -f test.bin -r 0 -s private-keys.txt -z keys -d 3

 LostCoins v3.0

 SEARCH MODE  : COMPRESSED
 DEVICE       : CPU
 CPU THREAD   : 11
 GPU IDS      : 0
 GPU GRIDSIZE : -1x128
 RANDOM MODE  : 0
 ROTOR SPEED  : HIGH (only counter)
 CHARACTERS   : 0
 PASSPHRASE   : private-keys.txt
 PASSPHRASE 2 : keys
 DISPLAY MODE : 3
 TEXT COLOR   : 15
 GPU REKEY    : 100000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 000001C2E880CA80
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Thu Sep  9 19:31:43 2021

  Random mode : 0
  Rotor       : Loading private keys from file private-keys.txt ...
  Loaded      : 25101305 private keys
  Rotor       : For large files use -t 11 max (1 core = ~30.000/s, 1 thread = ~5.000/s)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  [00:01:20] [CPU: 278,46 Kk/s] [T: 18,980,752] [F: 0]
  =================================================================================
  * PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x                                *
  * Priv(WIF) : p2pkh:L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm        *
  * Priv(HEX) : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  *
  =================================================================================
  [00:01:53] [CPU: 279,22 Kk/s] [T: 28,261,580] [F: 1]
```
## Mode 1 
### GPU fast sequential search from start to end of private keys
 - For GPU ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 1 -s ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f0000000 -z ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61ffffffff -m 250```

 ```
C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 1 -s ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f0000000 -z ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61ffffffff -m 250

 LostCoins v2.2

 SEARCH MODE  : COMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 288x512
 RANDOM MODE  : 1
 ROTOR SPEED  : HIGH (only counter)
 CHARACTERS   : 0
 PASSPHRASE   : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f0000000
 PASSPHRASE 2 : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61ffffffff
 DISPLAY MODE : 2
 TEXT COLOR   : 15
 GPU REKEY    : 250000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 0000026A880CC290
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Sun Sep  5 00:30:19 2021

  Random mode : 1
  Random      : Finding in a range
  Rotor GPU   : Reloading starting hashes every 250.000.000.000 on the counter
  Global start: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0000000 (256 bit)
  Global end  : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61FFFFFFFF (256 bit)
  Global range: 000000000000000000000000000000000000000000000000000000000FFFFFFF (28 bit)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)


  Divide the range FFFFFFF into 147456 cores and threads for quick search
  GPU 0 Thread 000000: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0000000 : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F000071C
  GPU 0 Thread 000001: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F000071C : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0000E38
  GPU 0 Thread 000002: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0000E38 : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0001554
  GPU 0 Thread 000003: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0001554 : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0001C70
                   .
  GPU 0 Thread 147455: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61FFFEF8E4 : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61FFFF0000

  Divide the range FFFFFFF into 147456 cores and threads for quick search
  GPU 0 Thread 000000: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0000000 : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F000071C
  GPU 0 Thread 000001: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F000071C : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0000E38
  GPU 0 Thread 000002: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0000E38 : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0001554
  GPU 0 Thread 000003: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0001554 : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0001C70
                   .
  GPU 0 Thread 147455: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61FFFEF8E4 : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61FFFF0000

  =================================================================================
  * PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x
  * Priv (WIF): p2pkh: L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm
  * Priv (HEX): BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
  =================================================================================

  =================================================================================
  * PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x
  * Priv (WIF): p2pkh: L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm
  * Priv (HEX): BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
  =================================================================================
  [00:00:02] [CPU+GPU: 1349,60 Mk/s] [GPU: 1349,60 Mk/s] [T: 2,717,908,992] [F: 2]
  =================================================================================
  * PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x
  * Priv (WIF): p2pkh: L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm
  * Priv (HEX): BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
  =================================================================================
  [00:00:04] [CPU+GPU: 1118,50 Mk/s] [GPU: 1118,50 Mk/s] [T: 4,529,848,320] [F: 3]

BYE
 ```
 ### CPU fast sequential search from start to end of private keys
  - For CPU ```LostCoins.exe -t 6 -f test.bin -r 1 -s ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f0000000 -z ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61ffffffff```
 ```
C:\Users\user>LostCoins.exe -t 6 -f test.bin -r 1 -s ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f0000000 -z ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61ffffffff

 LostCoins v2.2

 SEARCH MODE  : COMPRESSED
 DEVICE       : CPU
 CPU THREAD   : 6
 GPU IDS      : 0
 GPU GRIDSIZE : -1x128
 RANDOM MODE  : 1
 ROTOR SPEED  : HIGH (only counter)
 CHARACTERS   : 0
 PASSPHRASE   : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f0000000
 PASSPHRASE 2 : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61ffffffff
 DISPLAY MODE : 2
 TEXT COLOR   : 15
 GPU REKEY    : 100000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 0000022DBE39C690
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Sun Sep  5 00:38:00 2021

  Random mode : 1
  Random      : Finding in a range
  Rotor CPU   : 6 cores consistently seek Private key in range
  Global start: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0000000 (256 bit)
  Global end  : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61FFFFFFFF (256 bit)
  Global range: 000000000000000000000000000000000000000000000000000000000FFFFFFF (28 bit)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  [00:01:09] [CPU+GPU: 16,89 Mk/s] [GPU: 0,00 Mk/s] [T: 1,171,494,912] [F: 0]
  =================================================================================
  * PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x
  * Priv (WIF): p2pkh: L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm
  * Priv (HEX): BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
  =================================================================================

  =================================================================================
  * PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x
  * Priv (WIF): p2pkh: L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm
  * Priv (HEX): BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
  =================================================================================
  [00:01:11] [CPU+GPU: 16,88 Mk/s] [GPU: 0,00 Mk/s] [T: 1,205,753,856] [F: 2]
  
BYE
 ```
 ## Mode 2
 ### Exact accurate bit by bit search in a range
 - For GPU ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 2 -n 64 -m 99```
 ```
C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 2 -n 64 -m 99

 LostCoins v2.2

 SEARCH MODE  : COMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 288x512
 RANDOM MODE  : 2
 ROTOR SPEED  : HIGH (only counter)
 CHARACTERS   : 64
 PASSPHRASE   :
 PASSPHRASE 2 :
 DISPLAY MODE : 2
 TEXT COLOR   : 15
 GPU REKEY    : 99000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 000002483D4BD9E0
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Mon Aug 30 20:07:53 2021

  Random mode : 2
  Random      : Finding in a range
  Use range   : 64 (bit)
  Rotor       : Random generate hex in range 64
  Rotor GPU   : Reloading starting hashes in range 64 (bit) every 99.000.000.000 on the counter
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)

 [00:00:50] [CPU+GPU: 1117,89 Mk/s] [GPU: 1117,89 Mk/s] [T: 58,888,028,160] [F: 0]
 ```
  ### Exact accurate bit by bit search in a range 
 - For CPU ```LostCoins.exe -t 6 -f test.bin -r 2 -n 64 -d 2``` Speed
 - For CPU ```LostCoins.exe -t 6 -f test.bin -r 2 -n 64 -d 0``` Normal
 - For CPU ```LostCoins.exe -t 6 -f test.bin -r 2 -n 64 -d 1``` Slow
  ```
  C:\Users\user>LostCoins.exe -t 6 -f test.bin -r 2 -n 64 -d 1

 LostCoins v2.2

 SEARCH MODE  : COMPRESSED
 DEVICE       : CPU
 CPU THREAD   : 6
 GPU IDS      : 0
 GPU GRIDSIZE : -1x128
 RANDOM MODE  : 2
 ROTOR SPEED  : VERY SLOW (info+hashes+counter are displayed)
 CHARACTERS   : 64
 PASSPHRASE   :
 PASSPHRASE 2 :
 DISPLAY MODE : 1
 TEXT COLOR   : 15
 GPU REKEY    : 100000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 0000026D164FA970
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Mon Aug 30 20:09:46 2021

  Random mode : 2
  Random      : Finding in a range
  Use range   : 64 (bit)
  Rotor       : Random generate hex in range 64
  Rotor CPU   : 6 cores constant random generation hashes in 64 (bit) range
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

 [CA0E086D2926ED9C] (64 bit)                                                           [00:00:08] [CPU+GPU: 18,09 Mk/s] [GPU: 0,00 Mk/s] [T: 146,325,504] [F: 0]
  ```
 ## Mode 3
 ### Random search privat key (part+ -n values +par2 + -n value)
 - Run GPU: ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 3 -s 0123456789abcdef -n 10 -z fedcba9876543210 -m 5 -d 2```
 - Examples others combinations:
 - Run GPU: ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 3 -n 10 -z fedcba9876543210 -m 5 -d 0```
 - Run GPU: ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 3 -s 0123456789abcdef -z fedcba9876543210 -m 9 -d 0``` 
 - Run GPU: ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 3 -s 0123456789abcdeffedcba9876543210 -m 20 -d 0```
 
 ```
C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 3 -s 0123456789abcdef -n 10 -z fedcba9876543210 -m 5 -d 0

 LostCoins v2.2

 SEARCH MODE  : COMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 288x512
 RANDOM MODE  : 3
 ROTOR SPEED  : SLOW (info+counter are displayed)
 CHARACTERS   : 10
 PASSPHRASE   : 0123456789abcdef
 PASSPHRASE 2 : fedcba9876543210
 DISPLAY MODE : 0
 TEXT COLOR   : 15
 GPU REKEY    : 5000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 000002414C2BA720
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Mon Aug 30 20:15:15 2021

  Random mode : 3
  Random      : Part+value+part2+value
  Part        : 0123456789abcdef
  Value       : 10 x (0-f)
  Part 2      : fedcba9876543210
  Value 2     : 5 x (0-f)
  Example     : 0123456789abcdef[<<10>>]fedcba9876543210[<<5>>]
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)

 [0123456789abcdef3b9aa1788ffedcba987654321082fa5]
 ```
 ### Random search privat key (part+ -n values +par2 + -n value)
  - Run CPU: ```LostCoins.exe -t 6 -f test.bin -r 3 -s 0123456789abcdef -n 10 -z fedcba9876543210 -m 5 -d 0```
 ```
C:\Users\user>LostCoins.exe -t 6 -f test.bin -r 3 -s 0123456789abcdef -n 10 -z fedcba9876543210 -m 5 -d 0

 LostCoins v2.2

 SEARCH MODE  : COMPRESSED
 DEVICE       : CPU
 CPU THREAD   : 6
 GPU IDS      : 0
 GPU GRIDSIZE : -1x128
 RANDOM MODE  : 3
 ROTOR SPEED  : SLOW (info+counter are displayed)
 CHARACTERS   : 10
 PASSPHRASE   : 0123456789abcdef
 PASSPHRASE 2 : fedcba9876543210
 DISPLAY MODE : 0
 TEXT COLOR   : 15
 GPU REKEY    : 5000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 0000021C03E5B6C0
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Mon Aug 30 20:16:03 2021

  Random mode : 3
  Random      : Part+value+part2+value
  Part        : 0123456789abcdef
  Value       : 10 x (0-f)
  Part 2      : fedcba9876543210
  Value 2     : 5 x (0-f)
  Example     : 0123456789abcdef[<<10>>]fedcba9876543210[<<5>>]
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

 [0123456789abcdefa9292d9c0efedcba987654321059590]  [00:00:14] [CPU+GPU: 17,54 Mk/s] [GPU: 0,00 Mk/s] [T: 249,544,704] [F: 0]
 ```
  ## Mode 4 (BEST)
  ### Exact random search between specified ranges
 - Run GPU ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 4 -s 253 -z 254 -m 115```
 - Run CPU ```LostCoins.exe -t 6 -f test.bin -r 4 -s 64 -z 256```
 ```
C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 4 -s 64 -z 72 -m 155

 LostCoins v2.2

 SEARCH MODE  : COMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 288x512
 RANDOM MODE  : 4
 ROTOR SPEED  : HIGH (only counter)
 CHARACTERS   : 0
 PASSPHRASE   : 64
 PASSPHRASE 2 : 72
 DISPLAY MODE : 2
 TEXT COLOR   : 15
 GPU REKEY    : 155000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 000001A3E21DC5B0
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Mon Aug 30 20:16:55 2021

  Random mode : 4
  Random      : Finding in a ranges
  Start range : 64 (bit)
  End range   : 72 (bit)
  Rotor       : Generate random hex in ranges 64 <~> 72
  Rotor GPU   : Reloading new starting hashes in ranges every 155.000.000.000 on the counter
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)

 [00:00:34] [CPU+GPU: 1230,54 Mk/s] [GPU: 1230,54 Mk/s] [T: 41,674,604,544] [F: 0]
 ```
 ## Mode 5
 ### GPU Passphrases from file random 1-2-3 words (-n 1, -n 2 or -n 3) +hex value
 - Run GPU: ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f 01.bin -r 5 -n 3 -s test.txt``` HIGH
 - TEST only ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f 01.bin -r 5 -n 3 -s test.txt -d 0``` Slow
 - TEST only ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f 01.bin -r 5 -n 3 -s test.txt -d 1``` Very Slow
```
C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 288,512 -f 01.bin -r 5 -n 3 -s test.txt -d 0

 LostCoins v2.2

 SEARCH MODE  : COMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 288x512
 RANDOM MODE  : 5
 ROTOR SPEED  : SLOW (info+counter are displayed)
 CHARACTERS   : 3
 PASSPHRASE   : test.txt
 PASSPHRASE 2 :
 DISPLAY MODE : 0
 TEXT COLOR   : 15
 GPU REKEY    : 100000000000
 HASH160 FILE : 01.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 1,326,779 address

Bloom at 000001991D0FDC30
  Version     : 2.1
  Entries     : 2653558
  Error       : 0,0000010000
  Bits        : 76303525
  Bits/Elem   : 28,755175
  Bytes       : 9537941 (9 MB)
  Hash funcs  : 20

  Start Time  : Wed Sep  1 19:41:21 2021

  Random mode : 5
  Using       : Mnemonic words from file test.txt
  List        : 810 words
  Rotor       : Generation of 3 random words
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)

 [watter good day]
```

  ### CPU Passphrases from file random 1-2-3 words (-n ?) + hex value
 - Run CPU: ```LostCoins.exe -t 6 -f 01.bin -r 5 -s test.txt -n 2``` Speed  (only counter)
 - Run CPU: ```LostCoins.exe -t 6 -f 01.bin -r 5 -s test.txt -n 3 -d 0``` Normal (info+counter)
 - Run CPU: ```LostCoins.exe -t 6 -f 01.bin -r 5 -s test.txt -n 3 -d 1``` Slow  (info+hex+counter)
 
 ```
C:\Users\user>LostCoins.exe -t 6 -f test.bin -r 5 -s test.txt -n 3 -d 0

 LostCoins v2.2

 SEARCH MODE  : COMPRESSED
 DEVICE       : CPU
 CPU THREAD   : 6
 GPU IDS      : 0
 GPU GRIDSIZE : -1x128
 RANDOM MODE  : 5
 ROTOR SPEED  : SLOW (info+counter are displayed)
 CHARACTERS   : 3
 PASSPHRASE   : test.txt
 PASSPHRASE 2 :
 DISPLAY MODE : 0
 TEXT COLOR   : 15
 GPU REKEY    : 100000000000
 HASH160 FILE : 01.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 1,326,779 address

Bloom at 0000023966DABE40
  Version     : 2.1
  Entries     : 2653558
  Error       : 0,0000010000
  Bits        : 76303525
  Bits/Elem   : 28,755175
  Bytes       : 9537941 (9 MB)
  Hash funcs  : 20

  Start Time  : Wed Sep  1 19:34:10 2021

  Random mode : 5
  Using       : Mnemonic words from file test.txt
  List        : 810 words
  Rotor       : Generation of 3 random words
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

 [bitcoin is awesome]                       [00:00:42] [CPU+GPU: 14,81 Mk/s] [GPU: 0,00 Mk/s] [T: 638,662,656] [F: 0]
 ```
## Mode 6 
#### VanitySearch generator +-~ 4 (bit)
Run GPU:  ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 6 -n 256 -m 500```
 ```
C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 6 -n 256 -m 500

 LostCoins v2.2

 SEARCH MODE  : COMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 288x512
 RANDOM MODE  : 6
 ROTOR SPEED  : HIGH (only counter)
 CHARACTERS   : 256
 PASSPHRASE   :
 PASSPHRASE 2 :
 DISPLAY MODE : 2
 TEXT COLOR   : 15
 GPU REKEY    : 500000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 000002977F55B960
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Mon Aug 30 20:25:55 2021

  Random mode : 6
  Rotor GPU   : Reloading new starting hashes in range every 500.000.000.000 on the counter
  Range bit   : 256 (bit) Recommended -n 256 (256 searches in the 252-256 range and below)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)

 [00:00:18] [CPU+GPU: 1231,17 Mk/s] [GPU: 1231,17 Mk/s] [T: 21,743,271,936] [F: 0]
 ```
 #### For CPU Constant generation random new hashes in a given range +- ~ 4 bit
 - Run CPU:  ```LostCoins.exe -t 6 -f test.bin -r 0 -n 256 ```
 ```
C:\Users\user>LostCoins.exe -t 6 -f test.bin -r 6 -n 256 -d 1

 LostCoins v2.1

 SEARCH MODE  : COMPRESSED
 DEVICE       : CPU
 CPU THREAD   : 6
 GPU IDS      : 0
 GPU GRIDSIZE : -1x128
 RANDOM MODE  : 6
 ROTOR SPEED  : VERY SLOW (info+hashes+counter are displayed)
 CHARACTERS   : 256
 PASSPHRASE   :
 PASSPHRASE 2 :
 DISPLAY MODE : 1
 TEXT COLOR   : 15
 MAX FOUND    : 8
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 000001FE264FCDA0
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Fri Aug 27 19:47:26 2021

  Random mode : 6
  Rotor CPU   : 6 cores constant random generation hashes in range 256 (bit)
  Range bit   : 256 (bit) Recommended -n 256 (256 searches in the 252-256 range and below)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

 (255 bit) [494293D26D905A0F268AD5AC2A921DEF8CFF3ECFC9794DF3E4D0B39E651BE942]         [00:01:35] [CPU+GPU: 10,56 Mk/s] [GPU: 0,00 Mk/s] [T: 1,029,347,328] [F: 0]
 ```
## Building
- Microsoft Visual Studio Community 2019
- CUDA version [**10.22**](https://developer.nvidia.com/cuda-10.2-download-archive?target_os=Windows&target_arch=x86_64&target_version=10&target_type=exenetwork)
## Donation
- BTC: bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9
## License
LostCoins is licensed under GPL v3.0
## Disclaimer
ALL THE CODES, PROGRAM AND INFORMATION ARE FOR EDUCATIONAL PURPOSES ONLY. USE IT AT YOUR OWN RISK. THE DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY LOSS, DAMAGE OR CLAIM ARISING FROM USING THIS PROGRAM.
