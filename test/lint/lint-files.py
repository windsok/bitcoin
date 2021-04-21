#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
This checks that all files in the repository have correct filenames and permissions
"""

import os
import re
import sys
from subprocess import check_output
from typing import Optional, NoReturn

CMD_ALL_FILES = "git ls-files --full-name"
CMD_SOURCE_FILES = 'git ls-files --full-name -- "*.[cC][pP][pP]" "*.[hH]" "*.[pP][yY]" "*.[sS][hH]"'
CMD_SHEBANG_FILES = "git grep --full-name --line-number -I '^#!'"
ALLOWED_FILENAME_REGEXP = "^[a-zA-Z0-9/_.@][a-zA-Z0-9/_.@-]*$"
ALLOWED_SOURCE_FILENAME_REGEXP = "^[a-z0-9_./-]+$"
ALLOWED_SOURCE_FILENAME_EXCEPTION_REGEXP = (
    "^src/(secp256k1/|univalue/|test/fuzz/FuzzedDataProvider.h)"
)
ALLOWED_PERMISSION_NON_EXECUTABLES = 644
ALLOWED_PERMISSION_EXECUTABLES = 755
ALLOWED_EXECUTABLE_SHEBANG = {
    "py": [b"#!/usr/bin/env python3"],
    "sh": [b"#!/usr/bin/env bash", b"#!/bin/sh"],
}


def get_filename_extension(filename: str) -> Optional[str]:
    """
    Returns the full file extension for a given filename string.
    eg:
    'ci/lint_run_all.sh' -> 'sh'
    'ci/retry/retry' -> None
    'contrib/devtools/split-debug.sh.in' -> 'sh.in'
    """
    filename_parts = filename.split(os.extsep, 1)
    try:
        return filename_parts[1]
    except IndexError:
        return None


def check_all_filenames() -> int:
    """
    Checks every file in the repository against an allowed regexp to make sure only lowercase or uppercase
    alphanumerics (a-zA-Z0-9), underscores (_), hyphens (-), at (@) and dots (.) are used in repository filenames.
    """
    # We avoid using rstrip() to ensure we catch filenames which accidentally include trailing whitespace
    filenames = check_output(CMD_ALL_FILES, shell=True).decode("utf8").split("\n")
    filenames = [filename for filename in filenames if filename != ""]  # removes the trailing empty list element

    filename_regex = re.compile(ALLOWED_FILENAME_REGEXP)
    exit_code = 0
    for filename in filenames:
        if not filename_regex.match(filename):
            print(
                f"""File "{filename}" does not not match the allowed filename regexp ('{ALLOWED_FILENAME_REGEXP}')."""
            )
            exit_code = 1
    return exit_code


def check_source_filenames() -> int:
    """
    Checks only source files (*.cpp, *.h, *.py, *.sh) against a stricter allowed regexp to make sure only lowercase
    alphanumerics (a-z0-9), underscores (_), hyphens (-) and dots (.) are used in source code filenames.

    Additionally there is an exception regexp for directories or files which are excepted from matching this regexp.
    """
    # We avoid using rstrip() to ensure we catch filenames which accidentally include trailing whitespace
    filenames = check_output(CMD_SOURCE_FILES, shell=True).decode("utf8").split("\n")
    filenames = [filename for filename in filenames if filename != ""]  # removes the trailing empty list element

    filename_regex = re.compile(ALLOWED_SOURCE_FILENAME_REGEXP)
    filename_exception_regex = re.compile(ALLOWED_SOURCE_FILENAME_EXCEPTION_REGEXP)
    exit_code = 0
    for filename in filenames:
        if not filename_regex.match(filename) and not filename_exception_regex.match(filename):
            print(
                f"""File "{filename}" does not not match the allowed source filename regexp ('{ALLOWED_SOURCE_FILENAME_REGEXP}'), or the exception regexp ({ALLOWED_SOURCE_FILENAME_EXCEPTION_REGEXP})."""
            )
            exit_code = 1
    return exit_code


def check_all_file_permissions() -> int:
    """
    Checks all files in the repository match an allowed executable or non-executable file permission octal.

    Additionally checks that for executable files, the file contains a shebang line
    """
    filenames = check_output(CMD_ALL_FILES, shell=True).decode("utf8").strip().split("\n")
    exit_code = 0
    for filename in filenames:
        file_extension = get_filename_extension(filename)
        file_perms = int(oct(os.stat(filename).st_mode)[-3:])

        if file_perms == ALLOWED_PERMISSION_EXECUTABLES:
            shebang = open(filename, "rb").readline().rstrip(b"\n")

            # For any file with executable permissions the first line must contain a shebang
            if shebang[:2] != b"#!":
                print(
                    f"""File "{filename}" has permission {ALLOWED_PERMISSION_EXECUTABLES} (executable) and is thus expected to contain a shebang '#!'. Add shebang or do "chmod {ALLOWED_PERMISSION_NON_EXECUTABLES} {filename}" to make it non-executable."""
                )
                exit_code = 1

            # For certain file extensions that have been defined, we also check that the shebang conforms to a specific
            # allowable set of shebangs
            if file_extension in ALLOWED_EXECUTABLE_SHEBANG.keys():
                if shebang not in ALLOWED_EXECUTABLE_SHEBANG[file_extension]:
                    print(
                        f"""File "{filename}" is missing expected shebang """
                        + " or ".join(
                            [x.decode("utf-8") for x in ALLOWED_EXECUTABLE_SHEBANG[file_extension]]
                        )
                    )
                    exit_code = 1

        elif file_perms == ALLOWED_PERMISSION_NON_EXECUTABLES:
            continue
        else:
            print(
                f"""File "{filename}" has unexpected permission {file_perms}. Do "chmod {ALLOWED_PERMISSION_NON_EXECUTABLES} {filename}" (if non-executable) or "chmod {ALLOWED_PERMISSION_EXECUTABLES} {filename}" (if executable)."""
            )
            exit_code = 1

    return exit_code


def check_shebang_file_permissions() -> int:
    """
    Checks every file that contains a shebang line to ensure it has an executable permission
    """
    filenames = check_output(CMD_SHEBANG_FILES, shell=True).decode("utf8").strip().split("\n")

    # The git grep command we use returns files which contain a shebang on any line within the file
    # so we need to filter the list to only files with the shebang on the first line
    filenames = [filename.split(":1:")[0] for filename in filenames if ":1:" in filename]

    exit_code = 0
    for filename in filenames:
        file_extension = get_filename_extension(filename)
        file_perms = int(oct(os.stat(filename).st_mode)[-3:])

        if file_perms != ALLOWED_PERMISSION_EXECUTABLES:
            # These file types are typically expected to be sourced and not executed directly
            if file_extension in ["bash", "init", "openrc", "sh.in"]:
                continue

            # *.py files which don't contain an `if __name__ == '__main__'` are not expected to be executed directly
            if file_extension == "py":
                file_data = open(filename, "r", encoding="utf8").read()
                if not re.search("""if __name__ == ['"]__main__['"]:""", file_data):
                    continue

            print(
                f"""File "{filename}" contains a shebang line, but has the file permission {file_perms} instead of the expected executable permission {ALLOWED_PERMISSION_EXECUTABLES}. Do "chmod {ALLOWED_PERMISSION_EXECUTABLES} {filename}" (or remove the shebang line)."""
            )
            exit_code = 1
    return exit_code


def main() -> NoReturn:
    failed_tests = 0
    failed_tests += check_all_filenames()
    failed_tests += check_source_filenames()
    failed_tests += check_all_file_permissions()
    failed_tests += check_shebang_file_permissions()

    if failed_tests:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
