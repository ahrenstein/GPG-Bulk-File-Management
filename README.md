GPG Bulk File Management (gpg_files_bulk_manage.py)
==============================
This is a simple Python3 script that allows you to encrypt multiple files in a path without them being zipped into a single encrypted archive.
The directory structure of the specified root path to start with is preserved so /path/to/file.txt will result in /path/to/file.txt.gpg


Why did I write this?
---------------------
When using GPG Tools for Mac I discovered that encrypting more than one file at a time zips them together.
I wanted to encrypt multiple files at once, but still keep them as separate files for later individual decryption.  
Originally this was [done in PHP](https://github.com/ahrenstein/GPG2-Bulk-File-Encryptor) but that's not exactly a normal way to run a CLI script so I rewrote it in Python3.

Limitations
-----------
This script was develoepd on macOS so there are a few things assumed when using this script:

1. You have a GPG agent running in the background with a functioning PIN Entry application.
2. You are encrypting to a single GPG key that you have the secret key for in your keyring.
3. You have all required file permissions needed to operate on the folder you point this script to.
4. **Hidden files (files that begin with a `.` are ignored in both encryption and decryption operations)**

Requirements
------------
This script only requires a few libraries that are found in the [requirements.txt](SourceCode/requirements.txt) file.

1. `gnupg` provided by the `python-gnupg` package
2. `argparse` provided by the `argparse` package
3. `os` provided by Python3 core libraries
4. `sys` provided by Python3 core libraries
5. `datetime` privided by Python3 core libraries

Script Parameters
------------
There are a few parameters used by this script:

1. `-h` (Optional) - Help/Usage
2. Encrypt or Decrypt via:
    1. `-e`/`--encrypt` - Select this to encrypt files
    2. `-d`/`--decrypt` - Select this to decrypt files
3. `-p`/`--path` - The path to the folder and it's subfolders you want to encrypt all files in
4. `-k`/`--keyEmail` - The email address of the GPG key that should be able to decrypt the files. You can specify
this more than once. (Required when encrypting)
5. `--delete` - **Optional argument to delete the original files after the operation completes.**


Examples
--------
Here are a few examples of the command options and what they would do:

1. `python gpg_files_bulk_manage.py -p /path/to/taxes -e --delete -k me@gmail.com -k spouse@gmail.com` - Encrypt all files
in the folder `/path/to/taxes` with the keys for `me@gmail.com` and `spouse@gmail.com` as recipients. The original files
will be deleted.
2. `python gpg_files_bulk_manage.py -p /path/to/taxes -d` - Decrypt all files in the folder `/path/to/taxes` but
preserve the encrypted versions.
3. `python gpg_files_bulk_manage.py -p /path/to/taxes -e --delete -k me@gmail.com` - Encrypt all files in the folder
`/path/to/taxes` with only the key for `me@gmail.com` as a recipient. The original files will not be deleted.
 
Logging
-------
A log file named `bulk_gpg_{TIMESTAMP}.log` in the same directory of the script will contain the results of operation

