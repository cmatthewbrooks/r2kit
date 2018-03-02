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

Next, I like to identify "first-round" functions - functions that are likely developer-written (not thunks, wrappers, library code, etc) that have zero call instructions. These are good to rename quickly and also often make interesting use-cases for opcode-based YARA signatures.

```
!#pipe python /path/to/funclist.py -fr
```

With those listed, I will usually print the diassembly ('pdf' - 'print func disassembly') for examination, create zsignatures as appropriate, and rename where possible. 

If one of the "first-round" functions is interesting enough to warrant a YARA signature, functoyara.py can help. Make sure your r2 session is at the start of the function of interest.

```
!#pipe python /path/to/functoyara.py -n "YOUR RULE NAME" -a "YOUR NAME"
```
The -a flag is not needed if you set the constant in the YaraRule class within the script. The -n flag is optional if you'd rather set the rule name manually once it has been output to the screen. The functoyara.py script can stand alone outside the repository as it only uses r2pipes.

Next, I like to see "utility" functions - small functions frequently called by other functions.

```
!#pipe python /path/to/funclist.py -u
```

I will usually print each disassembly ('pdf' - 'print func disassembly') as well and rename where possible. Note that funclist.py can be run outside an active r2 session by using the -f flag and passing a file.

To be continued as more scripts are added...