Usage
=====

PDFCrack is a command-line utility designed for Mac OS X.  Compiling on other operating systems is probably pretty straight forward, but not completely trivial without a Makefile.

The command-line usage of PDFCrack is pretty basic.  PDFCrack current supports dictionary cracking, either with a file or through standard input, as well as raw brute force.  It is suggested to always use a dictionary before attempting to crack with brute force.

The usage of the command is as follows:

    pdfcrack [-d dictionary | --stdin] <PDF_FILE>

The ```--stdin``` option is used to specify standard input as the dictionary file, whereas -d specifies a dictionary file path on disk.  Note that no file paths given as command line arguments support the ~ home directory shortcut.

License
=======

This software is under no warranty.  Use at your own risk.  If, while using this program, a giant monkey or any other wild animal attacks you, it is not completely my fault, and I am not liable for it.
