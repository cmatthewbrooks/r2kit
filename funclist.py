'''
Author: Matt Brooks, @cmatthewbrooks

DESCRIPTION:

The funclist.py script obtains lists of specific
function types to help an analyst focus on a category
of functions. It currently can find the following
function types:

- First-round functions: Likely developer-written functions
that do not have any call instructions.

- Utility functions: Likely developer-written functions
called by at least 3 other functions.

ARGS:

Use the -fr flag to list first-round functions and use the
-u flag to list utility functions.

To use the script against a file instead of within an r2
session, use the -f flag with a /path/to/file.exe.

NOTES:

- This script can stand-alone outside an r2 session.

TODO:


'''

import os,sys
import argparse

import r2pipe
import r2utils as R2utils

class FuncList:

    def __init__(self, list_type, file=None):

        self.func_list = set()
        self.list_type = list_type
        self.file = file

        self.populate_list(self.list_type, self.file)

    # The next two methods are the init method and only external
    # method. Everything below the '###' line is internal-only.

    def populate_list(self, list_type, file=None):

        r2utils = R2utils.r2utils()

        if list_type == 'firstround':
            self.func_list.update(self.get_first_round_list(file))
        elif list_type == 'utility':
            self.func_list.update(self.get_utility_list(file))
        
    def print_functions(self):

        for func in sorted(self.func_list):
            print func

    ####################################################################

    def get_first_round_list(self, file=None):

        r2utils = R2utils.r2utils()
        first_round_funcs = []

        funcj_list = r2utils.get_funcj_list(file)

        for funcj in funcj_list:

            if (funcj['name'].startswith('fcn.') and 
                r2utils.check_is_first_round_func(funcj)):
                first_round_funcs.append(funcj['name'])
        
        return first_round_funcs

    def get_utility_list(self, file=None):

        r2utils = R2utils.r2utils()
        utility_funcs = []

        funcj_list = r2utils.get_funcj_list(file)

        for funcj in funcj_list:

            if (funcj['name'].startswith('fcn.') and 
                r2utils.check_is_utility_func(funcj)):
                utility_funcs.append(funcj['name'])

        return utility_funcs


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    list_type = parser.add_mutually_exclusive_group(required=True)
    list_type.add_argument('-u','--utility',action='store_true',
        help='Print the utility functions (used by 3 or more functions)')
    list_type.add_argument('-fr','--firstround',action='store_true',
        help='Print the first-round functions that do not call other functions.')

    parser.add_argument('-f','--file',help='The utility requires a binary to parse.')

    args = parser.parse_args()

    if not args:
        usage()

    if args:
        
        if args.utility:
            fl = FuncList('utility',args.file)
        elif args.firstround:
            fl = FuncList('firstround',args.file)
        else:
            print '\nCannot execute this list type.\n'
            sys.exit(1)

        fl.print_functions()

    else:

        print '\nCannot process file \'%s\'.\n' % args.file
        sys.exit(1)