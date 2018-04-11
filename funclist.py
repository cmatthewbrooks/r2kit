
# Author: Matt Brooks, @cmatthewbrooks

import os,sys
import argparse

import r2pipe
import r2utils as r2u

r2utils = r2u.R2Utils()

class FuncList:

    def __init__(self, list_type, file=None):

        self.func_list = set()
        self.list_type = list_type
        self.file = file

        self.populate_list(self.list_type, self.file)

    # The next two methods are the init method and only external
    # method. Everything below the '###' line is internal-only.

    def populate_list(self, list_type, file=None):

        if list_type == 'firstround':
            self.func_list.update(self.get_first_round_list(file))
        elif list_type == 'utility':
            self.func_list.update(self.get_utility_list(file))
        
    def print_functions(self):

        for func in sorted(self.func_list):
            print func

    ####################################################################

    def get_first_round_list(self, file=None):

        first_round_funcs = []

        funcj_list = r2utils.get_funcj_list(file)

        for funcj in funcj_list:

            if (funcj['name'].startswith('fcn.') and 
                r2utils.check_is_first_round_func(funcj)):
                first_round_funcs.append(funcj['name'])
        
        return first_round_funcs

    def get_utility_list(self, file=None):

        utility_funcs = []

        funcj_list = r2utils.get_funcj_list(file)

        for funcj in funcj_list:

            if (funcj['name'].startswith('fcn.') and 
                r2utils.check_is_utility_func(funcj)):
                utility_funcs.append(funcj['name'])

        return utility_funcs


def usage():

    print '\n' + sys.argv[0] + ' - generate various types of function lists.'

    print '''

    DESC:

        This utility allows a user to make or match hashed function
        signatures. Currently supported signature types include:

            - Hashes of r2's native zignature format
            - Hashes of function string set references

    EXAMPLES:

        $python funclist.py -fr

        $python funclist.py -u

        $python funclist.py -fr /bin/ls

    ARGS:

        -f - A file to pipe to an r2 session. If not provided, it is assumed
             the script is being invoked from within an r2 session.

        -fr - Print first-round functions (functions that do not call others)

        -u - Print utility functions (functions called by multiple others)

    '''


if __name__ == '__main__':

    if len(sys.argv) == 1:
        usage()
        sys.exit(1)

    parser = argparse.ArgumentParser()

    list_type = parser.add_mutually_exclusive_group(required=True)
    list_type.add_argument('-u','--utility',action='store_true',
        help='Print the utility functions (used by 3 or more functions)')
    list_type.add_argument('-fr','--firstround',action='store_true',
        help='Print the first-round functions that do not call other functions.')

    parser.add_argument('-f','--file',help='The utility requires a binary to parse.')

    args = parser.parse_args()


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