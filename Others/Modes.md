![alt text](https://github.com/phrutis/LostCoins/blob/main/Others/4.jpg "LostCoins")
## Project idea to find orphaned lost BitCoins
 - When Satoshi Nakamoto launched Bitcoin in 2009, he used Uncopressed addresses.
 - He found out about the existence of Compressed addresses only at the beginning of 2012.
 - The developer suggested using compressed addresses to ease the load on the network.
 - On March 31, 2012, BitCoin Core v0.6 was released in which Compressed was used to generate new addresses.
 - Outwardly, you will not see the difference between Legacy compressed and uncompressed addresses! 
 - From [dumps](https://blockchair.com/dumps) transactions on 03/31/2012, I collected a [database](https://github.com/phrutis/LostCoins/blob/main/Others/Un-all.txt) of uncompressed addresses with a positive balance for today.
 - Until 03/31/2012, most addresses were created using a [passphrase converted to a hash of Sha256](https://brainwalletx.github.io/) Bitcoin then cost a penny, the phrases were lost, and with them coins.
 - The task is to find a passphrase for old addresses from the database.For this task, LostCoins has many built-in word selection modes. 
 - Choose the best mode and start looking for coins 
You may be interested - [Why random is faster than brute force](https://github.com/phrutis/LostCoins/blob/main/Others/Random.md)
### For reference.
 - A total of 3,157,143 uncompressed addresses were created.
 - Today with a positive balance in total: 464.005 uncompressed [download](https://github.com/phrutis/LostCoins/blob/main/Others/Un-all.txt) addresses.
 - Sorted uncompressed addresses from 0.1 btc and higher. Happened: 75462 [download](https://github.com/phrutis/LostCoins/blob/main/Others/Un01.txt) addresses
 - Total words found [18972](https://allprivatekeys.com/hacked-brainwallets-with-balance) with addresses on which there were coins 
 - To check, we take any address from the file. We go to the blockchain and see the date of the first transaction. 
 - The first transaction must be before 03/31/2012, this confirms that the address is not compressed. 

- There is a ready-made file for tests is `test.bin` inside 4 words of 3 letters Uncomressed: cat, gaz, for, car Compressed abc, cop, run, zip. [Make your own](https://brainwalletx.github.io/) addressed for test
 
# An example of how to use dictionaries in LostCoins
- You can find dictionaries on the Internet and search for passphrases in them in mode 0
- For example, you can download the dictionary [**HERE**](https://www.weakpass.com/wordlist) 
- To work you need [EmEdotor](https://www.emeditor.com), easily handle files up to 16 TB. 
- There is garbage in the dictionaries, you need to clean it before using it in LostCoin! Otherwise, the program will stop running!!! 
- Use regex for quick cleanup **[^А-Яа-яA-Za-z0-9 `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]+**  It still throws an error. Use **[^\x1F-\x7F]+**
- In the program, select search, then replace. Find: [^А-Яа-яA-Za-z0-9 `~!@#$%&*()-_=+{}|;:'"<>,./?\r\n]+ replace with (empty) -> Replace All. Ready.
- You can manually separate logins from passwords by transferring them to a new line, etc. 
- If the dictionary is large 100-250GB +, divide it into files of ~ 2,000,000,000 lines. Select a service to split the document into multiple files. 
- Then you can add a dictionary to Lostcoins for search passphrases. 
- For search old coins in mode 0 USE **-u** or **-b**
- If you have any questions, write [**HERE**](https://github.com/phrutis/LostCoins/issues/16)
# How to use the Generator passphrases 
![alt text](https://github.com/phrutis/LostCoins/blob/main/Others/3.jpg "LostCoins")

Forked from [tp7309](https://github.com/tp7309/TTPassGen)
# Features

- generate password use combination permulation conditional rules and so on.
- support all characters or words(from wordlist option) that can make up a password, some built-in charset has been provided, such as lowercase letter list and numeric list.
- you can specify the order and frequency of each element in the word.
- simple rule format, and easy to use, rule could be defined similar regex's style.
- time-consuming estimates, output size estimates, and real-time progress reports.
- unicode word support by using wordlist option.
- generation of large amounts of passwords at once, no output size limit.
- support split output by file size.
# Quick Start
- Example: ```Generator.exe -r "Hello[?d] hi[?l]{1:5}@google.com" passphrases.txt -p 100```

```
C:\Users\user>Generator.exe -r "Hello[?d] hi[?l]{1:5}@google.com" passphrases.txt -p 100
found normal string: Hello
found normal string:  hi
found normal string: @google.com
mode: combination rule mode, global_repeat_mode: ?, part_size: 100.0 MB, dictlist: [], input dict file encoding: None
raw rule string: Hello[?d] hi[?l]{1:5}@google.com, analyzed rules: ['Hello', '[?d]', ' hi', '[?l]{1:5}', '@google.com']
estimated display size: 2.08 GB, generate dict...
100%|##############################################################| 82686760/82686760 [01:11<00:00, 1163966.35 word/s]
generate dict complete.
```
Out: ```22 files (100MB) Hello0 hia@google.com -> Hello9 hizyxwv@google.com```

### Example
- Run: ```Generator.exe -r "Petya [?u][?l][?l][?l][?d][?d]{1:5} Vasya" passphrases.txt -p 5000```

```
C:\Users\user>Generator.exe -r "Petya [?u][?l][?l][?l][?d][?d]{1:5} Vasya" passphrases.txt -p 5000
found normal string: Petya
found normal string:  Vasya
mode: combination rule mode, global_repeat_mode: ?, part_size: 4.88 GB, dictlist: [], input dict file encoding: None
raw rule string: Petya [?u][?l][?l][?l][?d][?d]{1:5} Vasya, analyzed rules: ['Petya ', '[?u]', '[?l]', '[?l]', '[?l]', '[?d]', '[?d]{1:5}', ' Vasya']
estimated display size: 3.57 TB, generate dict...
 12%|######7                                                    | 202586359/1759578752 [02:40<20:50, 1245206.33 word/s]
 ```
Out: ```Petya Aaaa00 Vasya -> Petya Zzzz99 Vasya```

### Example
- Russian language: ```Generator.exe -r "Вася [АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя0123456789]{1:3}" passphrases.txt -p 5000```
```
C:\Users\user>Generator.exe -r "Вася [АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя0123456789]{1:3}" passphrases.txt -p 5000
found normal string: Вася
mode: combination rule mode, global_repeat_mode: ?, part_size: 4.88 GB, dictlist: [], input dict file encoding: None
raw rule string: Вася [АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя0123456789]{1:3}, analyzed rules: ['Вася ', '[АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя0123456789]{1:3}']
estimated display size: 4.07 MB, generate dict...
100%|###################################################################| 427576/427576 [00:00<00:00, 989468.92 word/s]
generate dict complete.
```
Out: ```Вася А -> Вася 987```

### Generating private keys 
- Example: ```Generator.exe -r "ba7816bf8f01c[?d]ea414140de5dae2223b00[?d]61a396177a9cb410ff61f[0123456789abcdef]{7:7}" private-keys.txt -p 5000```
```
C:\Users\user>Generator.exe -r "ba7816bf8f01c[?d]ea414140de5dae2223b00[?d]61a396177a9cb410ff61f[0123456789abcdef]{7:7}" private-keys.txt -p 5000
found normal string: ba7816bf8f01c
found normal string: ea414140de5dae2223b00
found normal string: 61a396177a9cb410ff61f
mode: combination rule mode, global_repeat_mode: ?, part_size: 4.88 GB, dictlist: [], input dict file encoding: None
raw rule string: ba7816bf8f01c[?d]ea414140de5dae2223b00[?d]61a396177a9cb410ff61f[0123456789abcdef]{7:7}, analyzed rules: ['ba7816bf8f01c', '[?d]', 'ea414140de5dae2223b00', '[?d]', '61a396177a9cb410ff61f', '[0123456789abcdef]{7:7}']
estimated display size: 354.41 GB, generate dict...
 17%|####################1                                                                                                  | 248645274/1470792704 [03:25<15:50, 1286157.31 word/s]
 ```
Out: ```ba7816bf8f01c0ea414140de5dae2223b00061a396177a9cb410ff61f0123456 -> ba7816bf8f01c>>f<<ea414140de5dae2223b0>>ff<<61a396177a9cb410ff61>>ffffffff<<```

### If the size of the output file is greater than the size of ssd (hdd), the generator will NOT start!!! 

- Example: ```Generator.exe -r "H[?d]el[?d]lo goo[?l?u]{1:5}@google.[?d]com" passphrases.txt -p 100``` **<- 8.68 TB**

```
C:\Users\user>Generator.exe -r "H[?d]el[?d]lo goo[?l?u]{1:5}@google.[?d]com" passphrases.txt -p 100
found normal string: H
found normal string: el
found normal string: lo goo
found normal string: @google.
found normal string: com
mode: combination rule mode, global_repeat_mode: ?, part_size: 100.0 MB, dictlist: [], input dict file encoding: None
raw rule string: H[?d]el[?d]lo goo[?l?u]{1:5}@google.[?d]com, analyzed rules: ['H', '[?d]', 'el', '[?d]', 'lo goo', '[?l?u]{1:5}', '@google.', '[?d]', 'com']
estimated display size: 8.68 TB, generate dict...
  0%|                                                                                 | 0/680324096 [00:15<?, ? word/s]
```
- Try your own combinations of passphrase generation...
- If you have any questions, write [**HERE**](https://github.com/phrutis/LostCoins/issues/16)
![alt text](https://github.com/phrutis/LostCoins/blob/main/Others/2.jpg "LostCoins")

# Options
```
C:\Users\user>Generator.exe --help
Usage: Generator.exe [OPTIONS] OUTPUT
Options:
  -m, --mode INTEGER             generation mode:

                                 0 = combination rule mode
                                 [default: 0]
  -d, --dictlist TEXT            read wordlist from the file, multi files
                                 should by seperated by comma.
  -r, --rule TEXT                define word format, $0 means refer first
                                 file in dictlist option, some built-in char arrays:

                                 ?l = abcdefghijklmnopqrstuvwxyz
                                 ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
                                 ?d = 0123456789
                                 ?s = !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
                                 ?a = ?l?u?d?s
                                 ?q = ]

                                 example: [?dA]{1:2}$0
                                 view *RuleTypes* section for more information.
                                 [default: '']
  -c, --dict_cache INTEGER       each element in 'dictlist' option represents
                                 a dict file path, this option define the
                                 maximum amount of memory(MB) that can be used,
                                 increasing this value when the file is large
                                 may increase the build speed.  [default: 500]
  -g, --global_repeat_mode TEXT  global repeat mode, the value is used when the repeat mode of rule is not specified:

                                 ? = 0 or 1 repetitions
                                 * = 0 or more repetitions
                                 [default: ?]
  -p, --part_size INTEGER        when result data is huge, split package
                                 size(MB) will be applied, 0 is unlimited.
                                 [default: 0]
  -a, --append_mode INTEGER      whether append content to OUTPUT or not.
                                 [default: 0]
  -s, --seperator TEXT           wword seperator for output file, by default, Mac/Linudx: \n, Windows: \r\n".
                                 [default: Mac/Linux: \n, Windows: \r\n]
  --inencoding TEXT              dict file encoding.
  --outencoding TEXT             output file encoding.  [default: utf-8]
  --help                         Show this message and exit.
```

The output file uses `utf-8` encoding by default, it is recommended to use _Notepad++_ to open this file.

# RuleTypes

**Generator** supports three rule type, which can specified with the `--rule` option, you can use these rules at the same time.

## CharArrayRule

Generate a word based on the defined char array and repeat information.
Rule format：

```
[]{min_repeat:max_repeat:repeat_mode}
```

### CharArray

Use **[]** to wrap all chars.

Built-in char arrays:

```
//lowercase letters
?l = abcdefghijklmnopqrstuvwxyz

//Uppercase letters
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ

//Number list
?d = 0123456789

//Special character list
?s = !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~

//A collection of the above list
?a = ?l?u?d?s

//']', chars are wrapped with '[]', so if what put ']' into '[]', use '?q' instead of ']'.
?q = ]
```

For example, **[?d]** means to select char from number list.

### RepeatFormat

```
{min_repeat:max_repeat:repeat_mode}
```

For `CharArrayRule`, repeat times is the length of the word to be generated.

- `min_repeat`
  minimum repeat times
- `max_repeat`
  maximum repeat times
- `repeat_mode`
  char repeat mode

Define rule similar regex's style:

**[]** 1 repetitions.
`[123] -> 1 2 3`

**[]?** 0 or 1 repetitions.
`[123]? -> '' 1 2 3`

**[]{m:n:r}** repeat `m` to `n` times.
Repeat mode support `?` and `*`.

- repeatMode is '?', each char appears 0 or 1 times in word.

  `[123]{1:2:?} -> 1 2 3 12 13 21 23 31 32`

- repeatMode is '\*', each char appears 0 or more times in word.

  `[123]{1:2:*} -> 1 2 3 11 12 13 21 22 23 31 32 33`

Short rule format:

- **[]{m:n}**

  same as `[]{m:m:global_repeat_mode}`

- **[]{n}**

  same as `[]{n:n:global_repeat_mode}`

- **[]{n:r}**

  same as `[]{n:n:r}`

### Example

Generate 8-digit numeric password:

```
[?d]{8:8:*} or [?d]{8:*} or [1234567890]{8:8:*}
```

Generate an 8-digit numeric password, and each char in the password can appear at most once. Because the default value of `global repeat mode` is '?', so you can skip set repeat_mode:

```
[?d]{8:8:?} or [?d]{8}
```

Generate a password of 7 to 8 digits in length. The word can be composed of upper and lower case letters, numbers, and `_`:

```
[?l?u?d_]{7:8:*}
```

Use characters 1, 2, and 3 to generate a 4-digit password, and each character can appear at most once in each word:

```
[123]{4}  //Error! the length of word cannot be greater than the char array size.
[123]{2}[123]{2}  //Correct.
```

## StringArrayRule

Generate a word based on the defined string array and repeat information.
Rule format：

- `$(string1,string2){min_repeat:max_repeat:repeat_mode}`

  String array, each string is splited by comma, no spaces.

- `string`

  Normal string, same as `$(string){1:1:?}`.

Like `CharArrayRule`, but `StringArrayRule` does not support `Short rule format`.

### Example

Generate an 8-digit numeric password, end with `abc`:

```
[?d]{8:8:*}abc
```

Choose a number from (10,20,30), then append it after 'age':

```
age$(10,20,30){1:1:?}
```

Choose a number from (10,20,30), then append it after 'age', end with 'x' or 'y':

```
age$(10,20,30){1:1:?}[xy]
```

## DictRule

Read string from file(txt file). The dictionary file path can be specified by the `--dictlist` option. For example,`$0` means to refer 0th dictionary file.

Rule format:

```
$index
```

`DictRule` not support repeat mode.

### Example

content of `in.txt`:

```
ab
cd
```

content of `in2.txt`:

```
12
34
```

When `--dictlist` option defined as `in.dict,in2.dict` and _seperator_ is one space, run following command：

```bash
Generator.exe --dictlist "in.txt,in2.txt" --rule "$0[_]?$1" -s " " out.txt
```

Output:

```
ab12 ab34 ab_12 ab_34 cd12 cd34 cd_12 cd_34
```

