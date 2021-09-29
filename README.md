# LostCoins v3.1
 - This is a modified version [VanitySearch](https://github.com/JeanLucPons/VanitySearch/). 
Huge thanks [kanhavishva](https://github.com/kanhavishva) and to all developers whose codes were used in LostCoins.
## Quick start
- Сonvert addresses into binary hashes RIPEMD160 use [b58dec.exe](https://github.com/phrutis/LostCoins/blob/main/Others/b58dec.exe) Сommand: ```b58dec.exe addresses.txt base160.bin```
- It is important to sort the base160.bin file otherwise the Bloom search filter will not work as expected.
- To sort base160.bin use the program [RMD160-Sort.exe](https://github.com/phrutis/LostCoins/blob/main/Others/RMD160-Sort.exe) Сommand: ```RMD160-Sort.exe base160.bin hex160-Sort.bin``` 
- For Multi 3 GPUs use ```LostCoins.exe -t 0 -g -i 0,1,2 -x 256,256,256,256,256,256 -f test.bin -r 4 -s 252 -z 256 -m 500```  
- **Do not use the GPU+CPU will drop the speed!**
- You can search hashes160 of other coins, if it finds it, it will give an empty legacy address 1.. and positive private key and hex160
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
    -e, --nosse            Disable SSE hash function. Use for older CPU processor if it fails 
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

 LostCoins v3.1

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

 LostCoins v3.1

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
 - The range is divided into parts and many streams for quick searching. 
 - Unlike sequential search, you can find a private key in 2 seconds without waiting for a full search of the range. 
 - For GPU ```LostCoins.exe -t 0 -g -i 0 -x 256,256 -f test.bin -r 1 -s ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff0000000000 -z ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ffffffffffff```


 ```
C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 256,256 -f test.bin -r 1 -s ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff0000000000 -z ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ffffffffffff

 LostCoins v3.1

 SEARCH MODE  : COMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 256x256
 RANDOM MODE  : 1
 ROTOR SPEED  : HIGH (only counter)
 CHARACTERS   : 0
 PASSPHRASE   : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff0000000000
 PASSPHRASE 2 : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ffffffffffff
 DISPLAY MODE : 2
 TEXT COLOR   : 15
 GPU REKEY    : 100000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 0000021A8157B9C0
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Wed Sep 29 18:40:48 2021

  Random mode : 1
  Random      : Finding in a range
  Global start: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF0000000000 (256 bit)
  Global end  : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FFFFFFFFFFFF (256 bit)
  Global range: 000000000000000000000000000000000000000000000000000000FFFFFFFFFF (40 bit)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(256x256)

  [00:00:10] [CPU+GPU: 1024,06 Mk/s] [GPU: 1024,06 Mk/s] [T: 10,468,982,784] [F: 0]
  =================================================================================
  * PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x                                *
  * Priv(WIF) : p2pkh:L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm        *
  * Priv(HEX) : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  *
  =================================================================================
  [00:00:12] [CPU+GPU: 1016,64 Mk/s] [GPU: 1016,64 Mk/s] [T: 12,482,248,704] [F: 1]
 ```
 ### CPU search from start Private key 
  - One core, does not stop )
  - For CPU ```LostCoins.exe -t 1 -f test.bin -r 1 -s ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f0000000 -z ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61ffffffff -d 6```
 ```
C:\Users\user>LostCoins.exe -t 1 -f test.bin -r 1 -s ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f0000000 -z ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61ffffffff -d 6

  LostCoins v3.1

 SEARCH MODE  : COMPRESSED
 DEVICE       : CPU
 CPU THREAD   : 1
 GPU IDS      : 0
 GPU GRIDSIZE : -1x128
 RANDOM MODE  : 1
 CHARACTERS   : 0
 PASSPHRASE   : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f0000000
 PASSPHRASE 2 : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61ffffffff
 DISPLAY MODE : 6
 TEXT COLOR   : 15
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 0000020E08E8D950
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Thu Sep 23 23:55:03 2021

  Random mode : 1
  Random      : Finding in a range
  Global start: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0000000 (256 bit)
  Global end  : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61FFFFFFFF (256 bit)
  Global range: 000000000000000000000000000000000000000000000000000000000FFFFFFF (28 bit)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  [00:00:48] [BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61FBF88000] [CPU+GPU: 4,09 Mk/s] [GPU: 0,00 Mk/s] [T: 200,835,072] [F: 0]
  =================================================================================
  * PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x                                *
  * Priv(WIF) : p2pkh:L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm        *
  * Priv(HEX) : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  *
  =================================================================================
  [00:01:03] [BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61FF85F800] [CPU+GPU: 4,08 Mk/s] [GPU: 0,00 Mk/s] [T: 260,438,016] [F: 1]
 ```
 ## Mode 2
 ### Exact accurate bit by bit search in a range
 - For GPU ```LostCoins.exe -t 0 -g -i 0 -x 256,256 -f test.bin -r 2 -n 64 -m 99```
 ```
C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 2 -n 64 -m 99

 LostCoins v3.1

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

 LostCoins v3.1

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
 - Run GPU: ```LostCoins.exe -t 0 -g -i 0 -x 256,256 -f test.bin -r 3 -n 10 -z fedcba9876543210 -m 5 -d 0```
 - Run GPU: ```LostCoins.exe -t 0 -g -i 0 -x 256,256 -f test.bin -r 3 -s 0123456789abcdef -z fedcba9876543210 -m 9 -d 0``` 
 - Run GPU: ```LostCoins.exe -t 0 -g -i 0 -x 256,256 -f test.bin -r 3 -s 0123456789abcdeffedcba9876543210 -m 20 -d 0```
 
 ```
C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 256,256 -f test.bin -r 3 -s 0123456789abcdef -n 10 -z fedcba9876543210 -m 5 -d 0

 LostCoins v3.1

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

 LostCoins v3.1

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
 - Run GPU ```LostCoins.exe -t 0 -g -i 0 -x 256,256 -f test.bin -r 4 -s 252 -z 254 -m 200```
 - Run CPU ```LostCoins.exe -t 6 -f test.bin -r 4 -s 252 -z 256```
  ![133600417-1890faa6-52eb-4753-a163-f25a244f9fee](https://user-images.githubusercontent.com/82582647/133660453-5d04d5e4-847f-4ebc-9001-7f5793bf0483.png)
 ## Mode 5
 ### Start-continuation passphrase 
- Run CPU: ```LostCoins.exe -b -t 1 -f test.bin -r 5 -z AAA -d 5``` (SLOW) (HIGH use -d 3 )
- Out: AAA -> zzz -> ~~~ -> (space,space,space)
- Run CPU: ```LostCoins.exe -b -t 1 -f test.bin -r 5 -z Hello Word -d 5``` (SLOW) (HIGH use -d 3 )
- Out: Hello Word -> Hello Worf -> Hellz Zozz -> HeZbo Wz~~ -> Xerox Yaab -> Ye ar Xz ~~ -> Z ab cd ef 88 -> ~~~~~~
- Run CPU: ```LostCoins.exe -b -t 1 -f test.bin -r 5 -s BitCoin -z Turbo -d 5``` (SLOW) (HIGH use -d 3 )
- Out: BitCoinTurbo -> BitCoinTuxxx -> BitCoin Zip 9 -> BitCoin Yes ~ -> BitCoin(space,space,space,space,space)
```
C:\Users\user>LostCoins.exe -b -t 1 -f test.bin -r 5 -z AAA -d 5

 LostCoins v3.1

 SEARCH MODE  : COMPRESSED & UNCOMPRESSED
 DEVICE       : CPU
 CPU THREAD   : 1
 GPU IDS      : 0
 GPU GRIDSIZE : -1x128
 RANDOM MODE  : 5
 ROTOR SPEED  : HIGH (only counter)
 CHARACTERS   : 0
 PASSPHRASE   :
 PASSPHRASE 2 : AAA
 DISPLAY MODE : 5
 TEXT COLOR   : 15
 GPU REKEY    : 100000000000
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 000002084256B830
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Thu Sep 16 19:57:37 2021

  Mode        : 5
  Using       : Brute force Slow algorithm -t 1 USE ONLY 1 CPU CORE
  List        : ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$&'()*+,-./:;<=>?@[]^_`{|}~(space)
  Rotor       : Passphrase +AAA
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  [abc]                             [00:00:48] [CPU: 4,57 Kk/s] [T: 223,722] [F: 0]
  =================================================================================
  * PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x                                *
  * Priv(WIF) : p2pkh:L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm        *
  * Priv(HEX) : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  *
  =================================================================================
  [bar]                             [00:00:50] [CPU: 4,57 Kk/s] [T: 232,961] [F: 1]
  =================================================================================
  * PubAddress: 1Pk2zGBd4a7oUFY61JjXHLgzrH6Hqpartv                                *
  * Priv(WIF) : p2pkh:5KjekXVo3FPheAiXCJkuXJBu9WLfNxe5o35jYjLBZb8H53jJ2sT        *
  * Priv(HEX) : FCDE2B2EDBA56BF408601FB721FE9B5C338D10EE429EA04FAE5511B68FBF8FB9  *
  =================================================================================
  [car]                             [00:00:52] [CPU: 4,59 Kk/s] [T: 242,425] [F: 2]
  =================================================================================
  * PubAddress: 1FFtUDpR2CYZDc9TxzNpbNP1U6cXQ9Lq5c                                *
  * Priv(WIF) : p2pkh:5J9J63iW7s5p54T569qstediqNgBTLXpUmxUtQwsXTaHz3JCsKt        *
  * Priv(HEX) : 2B2961A431B23C9007EFE270C1D7EB79C19D4192D7CD2D924176EB0B19E7D2A1  *
  =================================================================================
  [cat]
  =================================================================================
  * PubAddress: 162TRPRZvdgLVNksMoMyGJsYBfYtB4Q8tM                                *
  * Priv(WIF) : p2pkh:5JiznUZskJpwodP3SR85vx5JKeopA3QpTK63BuziW8RmGGyJg81        *
  * Priv(HEX) : 77AF778B51ABD4A3C51C5DDD97204A9C3AE614EBCCB75A606C3B6865AED6744E  *
  =================================================================================
  [cop]
  =================================================================================
  * PubAddress: 15KqNGHFEViRS4WTYYJ4TRoDtSXH5ESzW9                                *
  * Priv(WIF) : p2pkh:L3BEabkqcsppnTdzAWiizPEuf3Rvr8QEac21uRVsYb9hjesWBxuF        *
  * Priv(HEX) : B1C02B717C94BD4243E83B5E98BA37FB273BC035E4AD8FC438EA4D07A1043F56  *
  =================================================================================
  [for]                             [00:00:58] [CPU: 4,60 Kk/s] [T: 270,424] [F: 5]
  =================================================================================
  * PubAddress: 19JxMTT1YqVHAx16NdvgULNajRYvrbFjm1                                *
  * Priv(WIF) : p2pkh:5HwfeuhdFscL9YTQCLT2952dieZEtKbzJ328b4CR1v6YUVLu2D7        *
  * Priv(HEX) : 10C22BCF4C768B515BE4E94BCAFC71BF3E8FB5F70B2584BCC8C7533217F2E7F9  *
  =================================================================================
  [gaz]
  =================================================================================
  * PubAddress: 1ERNpuxsGB6ytQKTwtCSmeyBTzmyw3uQAG                                *
  * Priv(WIF) : p2pkh:5KMdQbcUFS3PBbC6VgitFrFuaca3gBY4BJt4jpQ2YTNdPZ1CbuE        *
  * Priv(HEX) : CADC8EDAB738C1DF2CE192AF17E7D35EBBDCAF075E32ED2CC86F6D97C160DBAE  *
  =================================================================================
  [run]                             [00:01:20] [CPU: 4,59 Kk/s] [T: 372,718] [F: 7]
  =================================================================================
  * PubAddress: 14Nmb7rFFLdZhKaud5h7nDSLFQfma7JCz2                                *
  * Priv(WIF) : p2pkh:L31UCqx296TVRtgpCJspQJYHkwUeA4o3a2pvYKwRrCCAmi2NirDG        *
  * Priv(HEX) : ACBA25512100F80B56FC3CCD14C65BE55D94800CDA77585C5F41A887E398F9BE  *
  =================================================================================
  [zip]                             [00:01:35] [CPU: 4,54 Kk/s] [T: 436,933] [F: 8]
  =================================================================================
  * PubAddress: 1Mfw1us14DXJ8ju88iewjt48tswqEshU62                                *
  * Priv(WIF) : p2pkh:KyiR31LZTQ2hk1DRxEticnsQCA8tjFZcgJiKNaRArZME5fpfAjWj        *
  * Priv(HEX) : 4A70FE9AA6436E02C2DEA340FBD1E352E4EF2D8CE6CA52AD25D4B95471FC8BF2  *
  =================================================================================
                                    [00:03:14] [CPU: 0,00 Kk/s] [T: 804,357] [F: 9]
 ```
## Mode 6 
#### VanitySearch generator +-~ 4 (bit)
Run GPU:  ```LostCoins.exe -t 0 -g -i 0 -x 256,256 -f test.bin -r 6 -n 256 -m 500```
 ```
C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 256,256 -f test.bin -r 6 -n 256 -m 500

 LostCoins v3.1

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
 - Run CPU:  ```LostCoins.exe -t 6 -f test.bin -r 6 -n 256 ```
 ```
C:\Users\user>LostCoins.exe -t 6 -f test.bin -r 6 -n 256 -d 1

 LostCoins v3.1

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
