## Example Workflow

To start a session against a file:
```sh
$ r2 /path/to/malware.exe
```

Run sessionstart.py at the start. This will run a basic analysis sequence (aa; aac; aar) then rename functions. I did this because I seemed to have different naming preferences from r2's defaults.

```
!#pipe python /path/to/sessionstart.py
```

You can check the function listing to see how that went ('afll' - 'analyze func listing long').

Next, I like to identify "first-round" functions - functions that are likely developer-written (not thunks, wrappers, library code, etc) that have zero call functions. These are good to rename quickly and also often make interesting use-cases for opcode-based YARA signatures.

```
!#pipe python /path/to/funclist.py -fr
```

With those listed, I will usually print the diassembly ('pdf' - 'print func disassembly') for examination, create zsignatures as appropriate, and rename where possible. Next, I like to see "utility" functions - small functions frequently called by other functions.

```
!#pipe python /path/to/funclist.py -u
```

I will usually print each disassembly ('pdf' - 'print func disassembly') as well and rename where possible. Note that funclist.py can be run outside an active r2 session by using the -f flag and passing a file.

I will keep adding to this file as I develop r2kit.