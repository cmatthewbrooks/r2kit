# r2kit

## Overview

r2kit is a set of scripts to help with a workflow for malware code analysis using radare.

* sessionstarter.py - Run from inside an r2 session to auto rename imports, thunks, wrapper functions, and library functions.
* funclist.py - Run from inside an r2 session or externally against a binary to list certain function types.
* functoyara.py - Run from inside an r2 session to create a YARA signature for the bytes of the current function..

See [WORKFLOW](WORKFLOW.md) for more information.

## Thanks

Thanks to Sanoop [@s4n7h0](https://twitter.com/@s4n7h0) for a half-day workshop pushing my radare interest over the edge.

Thanks to Maxime [@Maijin212](https://twitter.com/@Maijin212) for a mailing-list response peaking my interest in r2pipes.

Thanks to Marion [@pinkflawd](https://twitter.com/@pinkflawd) for r2graphity which was extremely helpful for r2pipes examples.
