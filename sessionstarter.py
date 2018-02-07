
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

    def start_session(self):
        
        self.rename_import_jmp_funcs()
        self.rename_wrapper_funcs()
        self.rename_global_assignments()

        if self.sigs_dir:
            self.rename_bytes_signatures(self.sigs_dir)

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

    def rename_bytes_signatures(self,sigs_dir):

        r2 = r2pipe.open() 
        r2utils = R2utils.r2utils()
        
        for root, dirs, files in os.walk(sigs_dir):
            for name in files:
                if name.endswith('.z'):

                    r2.cmd('zo ' + os.path.join(root,name)) #Load the sigs from file
                    r2.cmd('z/') #Search for hits
                    zi_list = r2.cmd('zij') #Retrieve match information

                    #Rename the "bytes"-based zignature matches
                    if zi_list:
                        zij = json.loads(zi_list)
                        for z in zij:
                            if 'sign.bytes' in z['name']:
                                r2.cmd('s ' + str(z['offset']))
                                r2.cmd('afn ' + self.create_lib_sig_name(name,z['name']))

                    r2.cmd('z-*') #Remove the sigs

        r2.quit()

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