
## Example Workflow

To start a session against a file:
```sh
$ r2 /path/to/malware.exe
```

Run sessionstart.py at the start. This will run a basic analysis sequence (aa; aac; aar) then rename functions. I did this because I seemed to have different naming preferences from r2's defaults.

```
!#pipe python /path/to/sessionstart.py -l sigs/
```

The -l flag is optional in case you don't want to do signature matching from libary code. The main SessionStarter class also features a method called "auto_start" that can be used in batch mode. This would be useful to batch through a directory of files and only perform certain pipe operations to developer-generated functions (not imports or functions matching library code).

Carrying on, you can check the function listing to see how that went ('afll' - 'analyze func listing long').

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

To continue quick renaming efforts, looking at all the strings referenced by each function can be useful. Currently, this goes through the whole file but a helpful future limiter would be to use flagspaces and only run through functions marked with certain flags.

```
#!pipe python /path/to/funcstrings.py
```

The only requirement for funstrings is being in an active r2 session. It dumps raw JSON at the moment.

To be continued as more code is added...