
# Author: Matt Brooks, @cmatthewbrooks


import os,sys
import argparse
import json

import r2pipe

from r2utils import R2PipeUtility as r2pu
from r2utils import R2FuncUtility as r2fu
from r2utils import R2FlagUtility as r2flu
import sigs

class SessionStarter:

    default_sig_location = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), '/sigs/'
    )

    def __init__(self, input_obj = None):

        self.r2 = r2pu.get_analyzed_r2pipe_from_input(input_obj)

    def auto_start(self):

        self.rename_library_code(SessionStarter.default_sig_location)
        self.rename_common_funcs()

    def rename_library_code(self, location):

        # imported from sigs.py
        matcher = sigs.Matcher(location, self.r2)
        matcher.match()

    def rename_common_funcs(self):

        funcj_list = r2pu.get_funcj_list(self.r2)

        for funcj in funcj_list:

            if (r2fu.check_is_import_jmp_func(funcj)
                and funcj['name'].startswith('fcn.')):

                self.r2.cmd('s ' + str(funcj['addr']))
                self.r2.cmd('afn jmp_' +
                    r2fu.get_import_from_import_jmp_func(funcj)
                )

            elif (r2fu.check_is_wrapper_func(funcj)
                and funcj['name'].startswith('fcn.')):

                self.r2.cmd('s ' + str(funcj['addr']))

                self.r2.cmd('fs ' + r2flu.WRAPPER_FS)
                self.r2.cmd('f ' + str(funcj['addr']))

                self.r2.cmd('afn wrapper_' +
                    r2fu.get_call_from_wrapper(funcj).replace(' ','_')
                )

            elif (r2fu.check_is_global_assignment_func(funcj)
                and funcj['name'].startswith('fcn.')):

                self.r2.cmd('s ' + str(funcj['addr']))

                self.r2.cmd('fs ' + r2flu.GLOBAL_ASSIGNMENT_FS)
                self.r2.cmd('f ' + str(funcj['addr']))

                self.r2.cmd(
                    'afn globalassign_' + funcj['name'].replace('.','')
                )

def usage():

    print '\n' + sys.argv[0] + ' - a helper to start an r2 session.'

    print '''

    DESCRIPTION:

    The sessionstarter.py script is helpful when starting a new
    r2 session against a suspected malware target. It will handle
    auto-analysis as well as naming specific types of functions.

    The SessionStarter class and its auto_analysis method can also be used
    in other scripts to enable matching/renaming known code in a bulk method.
    The auto_analysis method will use signatures in the default '/sigs/'
    directory within r2kit.

    ARGS:

        -l - a location for signature files; if not given, only small common
             functions like thunks, imports, and wrappers will be renamed.

    '''


if __name__ == '__main__':

    if len(sys.argv) == 1:
        usage()
        sys.exit(1)

    parser = argparse.ArgumentParser()

    parser.add_argument('-l','--location',
        help = 'Location of signatures for matching (file or directory).')

    args = parser.parse_args()

    r2 = r2pipe.open()

    if args.location and not os.path.exists(args.location):

        print args.location + ' is not a valid signature location.'
        sys.exit(1)

    elif args.location and os.path.exists(args.location):

        ss = SessionStarter(r2)
        ss.rename_library_code(args.location)
        ss.rename_common_funcs()

    elif not args.location:

        ss = SessionStarter(r2)
        ss.rename_common_funcs()

    r2.quit()
