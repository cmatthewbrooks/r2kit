# r2kit

## Overview

r2kit is a set of scripts to help with a workflow for malware code analysis using radare.

* sessionstarter.py - Run from inside an r2 session to auto rename imports, thunks, wrapper functions, and library functions.
* funclist.py - Run from inside an r2 session or externally against a binary to list certain function types.

See WORKFLOW.md for more information.

## Todo

* Port a YARA generator script for function opcode bytes
* Write script to create zignatures (.z files) for different standard library files to include in this project
* Write script for basic function assistance aka resolving indirect calls, etc.
* Write script to analyze call-chain gadgets in individual functions; experiment with auto-renaming
* Finalize string set matching script (currently hacked together targeting sqlite3 string sets; need to clean up)
* Merge maldata (separate personal project; currently unreleased) to make this my "one-stop shop" for r2 sessions, individual malware binary code analysis, or analysis of directories of malware
* Rewrite using python3 to help Marcus LaFerrera's mood

## Thanks

Thanks to Sanoop (@s4n7h0) for a half-day workshop pushing my radare interest over the edge.

Thanks to Maxime (@Maijin212) for a mailing-list response peaking my interest in r2pipes.

Thanks to Marion (@pinkflawd) for r2graphity which was extremely helpful for r2pipes examples.