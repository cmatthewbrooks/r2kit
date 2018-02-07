
import r2pipe 
import os,sys
import argparse

import r2utils as R2utils

class FuncList:
    '''
    '''

    def __init__(self, list_type, file=None):

        #Set all properties
        self.func_list = set()
        self.list_type = list_type
        self.file = file

        #Populate the list
        self.populate_list(self.list_type, self.file)

    def populate_list(self, list_type, file=None):

        r2utils = R2utils.r2utils()

        if file and list_type == 'utility':
            self.func_list.update(r2utils.get_utility_list_from_file(file))
        elif file and list_type == 'firstround':
            self.func_list.update(r2utils.get_first_round_list_from_file(file))
        elif not file and list_type == 'utility':
            self.func_list.update(self.get_utility_list_from_session())
        elif not file and list_type == 'firstround':
            self.func_list.update(self.get_first_round_list_from_session())
        
    def print_functions(self):

        for func in sorted(self.func_list):
            print func

    def get_first_round_list_from_session(self):

        r2utils = R2utils.r2utils()
        first_round_funcs = []

        funcj_list = r2utils.get_funcj_list_from_session()

        for funcj in funcj_list:

            if r2utils.check_is_first_round_func(funcj):
                first_round_funcs.append(funcj['name'])
        
        return first_round_funcs

    def get_utility_list_from_session(self):

        r2utils = R2utils.r2utils()
        utility_funcs = []

        funcj_list = r2utils.get_funcj_list_from_session()

        for funcj in funcj_list:

            if r2utils.check_is_utility_func(funcj):
                utility_funcs.append(funcj['name'])

        return utility_funcs

    def get_first_list_funcs_from_file(self, file):

        r2utils = R2utils.r2utils()
        first_round_funcs = []

        funcj_list = self.get_funcj_list_from_file(file)

        for funcj in funcj_list:

            if r2utils.check_is_first_round_func(funcj):
                first_round_funcs.append(funcj['name'])
        
        return first_round_funcs

    def get_utility_list_from_file(self, file):

        r2utils = R2utils.r2utils()
        utility_funcs = []

        funcj_list = self.get_funcj_list_from_file(file)

        for funcj in funcj_list:

            if r2utils.check_is_utility_func(funcj):
                utility_funcs.append(funcj['name'])

        return utility_funcs



if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    list_type = parser.add_mutually_exclusive_group(required=True)
    list_type.add_argument('-u','--utility',action='store_true',help='Print the utility functions (used by 3 or more functions)')
    list_type.add_argument('-fr','--firstround',action='store_true',help='Print the first-round functions that do not call other functions.')

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