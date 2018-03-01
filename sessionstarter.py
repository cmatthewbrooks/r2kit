'''
Author: Matt Brooks, @cmatthewbrooks

DESCRIPTION:

The sessionstarter.py script is helpful when starting a new
r2 session against a suspected malware target. It will handle
auto-analysis as well as naming specific types of functions.

ARGS:

Use the optional -d flag to point to a directory of zsig files
where each file has a .z extention.

NOTES:

- When using zsigs from a signature file, only the "bytes" sigs
  are considered. The "refs" and "graphs" sigs are too loose for
  my taste and in the instances where they match correctly, a
  "bytes" signature exists for the same function. If you determine
  a case where the "refs" or "graphs" signatures were useful without
  an existing "bytes" signature, please file a Github issue.

TODO:

- Redesign structure so each "rename" function does not open and
  close a separate pipe.

- Add optional -f flag to provide a file arg similar to the -d
  flag. There may be use cases where an analyst wants to use a
  single zsig file that may be in a directory of other files.

'''

import os,sys
import argparse
import json

import r2pipe 
import r2utils as R2utils

class SessionStarter:

    def __init__(self, directory=None):
        self.sigs_dir = directory
        r2 = r2pipe.open()
        r2.cmd('aa; aac; aar')
        r2.quit()

    # The start_session is the only method meant to be
    # called outside the class.

    def start_session(self):
        
        if self.sigs_dir:
            pass
            #TODO: Implement sigs.py Handlers logic.

        self.rename_import_jmp_funcs()
        self.rename_wrapper_funcs()
        self.rename_global_assignments()


    ###############################################################################

    # These methods all handle categorical renaming and depend on the r2utils file
    # for function categorization.


    def rename_import_jmp_funcs(self):

        r2 = r2pipe.open() 
        r2utils = R2utils.r2utils()

        funcj_list = r2utils.get_funcj_list_from_session()

        for funcj in funcj_list:

            if r2utils.check_is_import_jmp_func(funcj):

                r2.cmd('s ' + str(funcj['addr']))
                r2.cmd('afn jmp_' + r2utils.get_import_from_import_jmp_func(funcj))

        r2.quit()

    def rename_wrapper_funcs(self):

        r2 = r2pipe.open() 
        r2utils = R2utils.r2utils()

        funcj_list = r2utils.get_funcj_list_from_session()

        for funcj in funcj_list:

            if r2utils.check_is_wrapper_func(funcj):
                r2.cmd('s ' + str(funcj['addr']))
                r2.cmd('afn wrapper_' + (r2utils.get_call_from_wrapper(funcj)).replace(' ','_'))

        r2.quit()

    def rename_global_assignments(self):

        r2 = r2pipe.open() 
        r2utils = R2utils.r2utils()

        funcj_list = r2utils.get_funcj_list_from_session()

        for funcj in funcj_list:

            if r2utils.check_is_global_assignment_func(funcj):

                r2.cmd('s ' + str(funcj['addr']))
                r2.cmd('afn globalassign_' + funcj['name'].replace('.',''))

        r2.quit()

    # A small method to create a new function name. By default, r2 will only match functions
    # and include that information as strings. The method above renames based on sane defaults.

    def create_lib_sig_name(self,lib,func):
        
        if 'fcn.' in func:
            return 'unknownlibfunc_' + lib[:len(lib)-2] + '_func_' + func[len('sign.bytes.fcn.'):]
        elif 'sym.' in func:
            return func[len('sign.bytes.sym.'):]
        else:
            return func


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-d','--dir',help='A directory of zsig files to use for library function renaming.')
    args = parser.parse_args()

    if args.dir and not os.path.isdir(args.dir):
        print args.dir + ' is not a directory.'
        sys.exit(1)
    else:
        ss = SessionStarter(args.dir)
        ss.start_session()