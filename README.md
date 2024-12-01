# PSP prxldr plugin for IDA

This is an updated version of prxldr for IDA v7.5 sp3.


## Install
To install copy the files "prxldr.dll" and "prxldr64.dll" into the "IDA/loaders" directory.
If you also copy the file "psplibdoc.xml" into the "IDA/loaders" directory this plugin will use it to correctly name imports and exports.


## Credits
* xyzz wrote prxldr
* balika011 updated prxldr for a newer version of IDA
* xorloser updated prxldr for IDA v7.5 sp3, fixed some 32bit pointer stuff and added decompiler setup (requires MIPS hexrays decompiler to decompile).
* thecobra created the bundled psplibdoc.xml in the releases zip (afaik)


## Limitations
Does not support encryped PRX files.

Does not properly support the PSP ABI when decompiling (but works decently).
It seems the PSP ABI is actually some custom sony "mips eabi" thing,
but IDA only lets us choose between o32 and n32.
* o32 has 32bit registers and supports up to 4 registers as params for functions.
* n32 has 64bit registers and supports up to 8 registers as params for functions.

I chose n32 since it will show params for functions correctly.
It will however show 64bit values for immediate values which will look
weird for immediate values that have the upper bit set.

This means that you will see:
	```some_var = 0xFFFFFFFF80000000```
instead of
	```some_var = 0x80000000```


## History
### 20210304
First release by xorloser
