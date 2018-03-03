
# Library Information

## Status

Currently, there are only library signature hashes for the Visual C Compiler. Please submit issues or pull requests for additional signature hash files.

## Visual C/C++ Library Notes

The earliest Visual Studio library code for which signatures have been created in this repository is VC 6.0. Historical information for Visual C/C++ can be found at these references:

* [Microsoft Compiler Versions](https://www.spearfoot.net/microsoft-c-cpp-compiler-versions/) 
* [Version History of VC, MFC, and ATL](http://mariusbancila.ro/blog/2015/08/12/version-history-of-vc-mfc-and-atl/)

Using [this](https://support.microsoft.com/en-sg/help/259403/how-to-obtain-the-visual-c-6-0-run-time-components) information from Microsoft, the following represents the list of library code files from VC6.0:

* Asycfilt.dll - Used for ActiveX controls; no longer included in Visual C++
* Atl.dll - Active Template Library for use in programming COM objects; Not redistributable after VS2012
* Comcat.dll - Used for ActiveX controls; no longer included in Visual C++ 
* Comctl32.dll - Used for Visual Styles
* Mfc42.dll - Microsoft Foundational Classes
* Mfc42u.dll - Microsoft Foundational Classes with Unicode support
* Msvcirt.dll - Unknown
* Msvcp60.dll - Standard C++ Library
* Msvcrt.dll - Visual C Runtime Library
* Oleaut32.dll - Used for ActiveX controls; no longer included in Visual C++
* Olepro32.dll - Used for ActiveX controls; no longer included in Visual C++

Some of the above files were merged or otherwise eliminated in future versions of Visual Studio.

The Universal CRT was introduced in Visual Studio 2015. See these links for recent changes to the CRT:

* [Introducing the Universal CRT](https://blogs.msdn.microsoft.com/vcblog/2015/03/03/introducing-the-universal-crt/)
* [The Great C Runtime Refactoring](https://blogs.msdn.microsoft.com/vcblog/2014/06/10/the-great-c-runtime-crt-refactoring/)