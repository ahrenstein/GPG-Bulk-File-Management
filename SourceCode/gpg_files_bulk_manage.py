#!/usr/bin/env python3
"""A simple Python script that allows you to encrypt/decrypt
multiple files in a path without them being zipped into a single encrypted archive."""
#
# Python Script:: gpg_files_bulk_manage.py
#
# Linter:: pylint
#
# Copyright 2019, Matthew Ahrenstein, All Rights Reserved.
#
# Maintainers:
# - Matthew Ahrenstein: matt@ahrenstein.com
#
# See LICENSE
#

import argparse
import datetime
import os
import sys
import gnupg


# Walk directory for files
def get_files(path):
    """This function recursively crawls a directory for files
    and saves them to a list with their full path

    Args:
        path: The path to a folder of files to perform bulk actions on

    Returns:
        files: An array of files with their full paths

    """
    files = [] # Instantiate variable for returning list of files
    # Walk the entire path
    # Using _ instead of directories makes it a temporary discarded variable
    # This is more proper and will not ding the linting score
    for root, _, filenames in os.walk(path):
        # Look only for files
        for filename in filenames:
            # Ignore hidden files
            if filename[0] != ".":
                file = os.path.join(root, filename)
                files.append(file)
    return files


# Bulk Encrypt Files
def gpg_bulk_encrypt(key_emails, delete_flag, path, log_file):
    """This function recursively checks the path provided
    for all non .gpg files and encrypts them

    Args:
        key_emails: The list of email(s) belonging to the GPG key(s) involved
        delete_flag: True or False flag to delete the original file when performing actions
        path: The path to a folder of files to perform bulk actions on
        log_file: The open log file that entries are written to

    """
    now = datetime.datetime.now()
    log_file.write("%s: Scanning %s for files\n" % (now.strftime("%m/%d/%Y-%H:%M:%S"), path))
    log_file.flush()
    list_of_files = get_files(path)

    # Instantiate GPG class with agent use
    gpg = gnupg.GPG(use_agent=True)
    # Find matching keys
    matching_keys = gpg.list_keys(secret=True, keys=key_emails)

    # Verify the key provided is a secret key
    if matching_keys == []:
        now = datetime.datetime.now()
        error_msg = "%s: FATAL ERROR! GPG secret key for %s not found in GPG agent!" \
                    % (now.strftime("%m/%d/%Y-%H:%M:%S"), key_emails)
        log_file.write(error_msg + "\n")
        log_file.flush()
        print(error_msg)
        log_file.close()
        sys.exit(1)

    # Begin encryption
    for file in list_of_files:
        # Do not attempt to encrypt already encrypted files
        if ".gpg" not in file:
            now = datetime.datetime.now()
            log_message = "%s: Encrypting %s so only %s can decrypt it!" \
                          % (now.strftime("%m/%d/%Y-%H:%M:%S"), file, key_emails)
            log_file.write(log_message + "\n")
            log_file.flush()
            print(log_message)
            with open(file, 'rb') as plain_file:
                _ = gpg.encrypt_file(  # Using that temporary discarded variable again
                    file=plain_file,
                    recipients=key_emails,
                    armor=False,
                    always_trust=True,
                    output=file + ".gpg")
            if delete_flag:
                now = datetime.datetime.now()
                log_message = "%s: DELETING %s NOW THAT IT IS ENCRYPTED!" \
                              % (now.strftime("%m/%d/%Y-%H:%M:%S"), file)
                log_file.write(log_message + "\n")
                log_file.flush()
                print(log_message)
                os.remove(file)
        else:
            now = datetime.datetime.now()
            log_message = "%s: Skipping %s because it's a .gpg file and " \
                          "is probably already encrypted!" \
                          % (now.strftime("%m/%d/%Y-%H:%M:%S"), file)
            log_file.write(log_message + "\n")
            log_file.flush()
            print(log_message)


# Bulk Decrypt Files
def gpg_bulk_decrypt(delete_flag, path, log_file):
    """This function recursively checks the path provided
    for all .gpg files and decrypts them

    Args:
        delete_flag: True or False flag to delete the original file when performing actions
        path: The path to a folder of files to perform bulk actions on
        log_file: The open log file that entries are written to

    """
    now = datetime.datetime.now()
    log_file.write("%s: Scanning %s for files\n" % (now.strftime("%m/%d/%Y-%H:%M:%S"), path))
    log_file.flush()
    list_of_files = get_files(path)

    # Instantiate GPG class with agent use
    gpg = gnupg.GPG(use_agent=True)

    # Begin encryption
    for file in list_of_files:
        # Do not attempt to decrypt a non-encrypted file
        if ".gpg" in file:
            now = datetime.datetime.now()
            log_message = "%s: Decrypting %s!" \
                          % (now.strftime("%m/%d/%Y-%H:%M:%S"), file)
            log_file.write(log_message + "\n")
            log_file.flush()
            print(log_message)
            with open(file, 'rb') as encrypted_file:
                _ = gpg.decrypt_file(  # Using that temporary discarded variable again
                    file=encrypted_file,
                    always_trust=True,
                    output=file.replace(".gpg", "")
                )
            if delete_flag:
                now = datetime.datetime.now()
                log_message = "%s: DELETING %s NOW THAT IT IS DECRYPTED!" \
                              % (now.strftime("%m/%d/%Y-%H:%M:%S"), file)
                log_file.write(log_message + "\n")
                log_file.flush()
                print(log_message)
                os.remove(file)
        else:
            now = datetime.datetime.now()
            log_message = "%s: Skipping %s because it's not a .gpg file and " \
                          "is probably already decrypted!" \
                          % (now.strftime("%m/%d/%Y-%H:%M:%S"), file)
            log_file.write(log_message + "\n")
            log_file.flush()
            print(log_message)


def main(action, key_emails, delete_flag, path):
    """The main function where we start logging and call
    all other functions from

    Args:
        action: The action to perform (encrypt, or decrypt)
        key_emails: The list of email(s) belonging to the GPG key(s) involved
        delete_flag: True or False flag to delete the original file when performing actions
        path: The path to a folder of files to perform bulk actions on

    """
    # First thing we do is open a log file for writing
    now = datetime.datetime.now()
    log_file_name = 'bulk_gpg_%s.log' % (now.strftime("%m%d%Y%H%M%S"))
    log_file = open(log_file_name, 'a')
    actions_chosen = "Run Configuration:\n" \
                     "Action: %s\n" \
                     "Path: %s\n" \
                     "Encryption Key: %s\n" \
                     "Delete Originals: %s" % (action, path, key_emails, delete_flag)
    log_file.write("%s: Run starting.\n" % (now.strftime("%m/%d/%Y-%H:%M:%S")))
    log_file.write("%s: %s\n" % (now.strftime("%m/%d/%Y-%H:%M:%S"), actions_chosen))
    log_file.flush()
    if action == "encrypt":
        gpg_bulk_encrypt(key_emails, delete_flag, path, log_file)
    else:
        gpg_bulk_decrypt(delete_flag, path, log_file)
    log_file.close()
    sys.exit()


if __name__ == '__main__':
    # This function parses and return arguments passed in
    # Assign description to the help doc
    PARSER = argparse.ArgumentParser(
        description='A simple Python script that allows you to encrypt/decrypt\
                    multiple files in a path without them being zipped into\
                    a single encrypted archive.')
    # Add arguments
    ACTION = PARSER.add_mutually_exclusive_group(required=True)
    ACTION.add_argument(
        '-e', '--encrypt', help="Encrypt files", action='store_true'
    )
    ACTION.add_argument(
        '-d', '--decrypt', help="Decrypt files", action='store_true'
    )
    PARSER.add_argument(
        '-p', '--path', type=str,
        help='path to directory to encrypt/decrypt', required=True)
    PARSER.add_argument(
        '--delete', help='Delete original files after actioned (Optional)',
        required=False, action='store_true')
    PARSER.add_argument(
        '-k', '--keyEmails', type=str, action='append',
        help='A GPG key email address to encrypt with.'
             'You can specify this more than once.', required=False)
    # Array for all arguments passed to script
    ARGS = PARSER.parse_args()
    if ARGS.encrypt and ARGS.keyEmails is None:
        PARSER.error("-k/--keyEmail is required if you are encrypting")
    # Assign args to variables
    if ARGS.encrypt:
        ARG_ACTION = "encrypt"
    else:
        ARG_ACTION = "decrypt"
    ARG_PATH = ARGS.path
    ARG_KEYS = ARGS.keyEmails
    ARG_DELETE = ARGS.delete
    main(ARG_ACTION, ARG_KEYS, ARG_DELETE, ARG_PATH)
