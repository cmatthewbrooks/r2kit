'''
Author: Matt Brooks, @cmatthewbrooks

DESCRIPTION:

The sigs.py script creates Python dicts of func name/hash
pairs for different types of intake patterns. Currently, the 
native r2 zignatures can serve as an intake (an experimental
string set structure is coming soon). These intake patterns 
are then hashed for smaller storage size and performance 
gains on matching.

ARGS:

 - mode - use the -g flag if generating; use the -m flag if 
   you're matching in-session.

 - sigtype - use the -z flag if generating/matching based on
   zignature intakes; the -ss flag is set up for string sets
   but the Handler class has not been implemented yet.

 - input - use the -i flag to pass input - a file or dir to 
   source from if generating or match from if matching

 - output - use the -o flag when matching to define the
   output file.


NOTES:

- 

TODO:

- Implement the StringSetHandler class.

- Redesign using inheritance from a parent class.

'''

import os,sys
import argparse
import hashlib
import re
import json

import r2pipe

class ZigHandler:

    def __init__(self):

        self.hashes = {}
        self.temphashes = set()

    def generate_hashes_from_session(self):

        self.generate_hashes()

    def generate_hashes_from_input(self, infile, outfile):

        # Execute based on inputs and output
        if os.path.isdir(infile) and self.check_outfile(outfile):

            self.generate_hashes_from_dir(infile)
            self.write_zighash_file(outfile)
        
        elif os.path.isfile(infile) and self.check_outfile(outfile):
        
            self.generate_hashes(infile)
            self.write_zighash_file(outfile)
        
        else:
        
            print "\nCannot create from input.\n"
            sys.exit(1)

    def generate_hashes_from_dir(self, directory):
        
        for file in self.sorted_alphanumeric(os.listdir(directory)):

            print "Generating zig hashes for " + os.path.join(directory,file)
            self.generate_hashes(os.path.join(directory,file))

    def generate_hashes(self, infile=None):
        
        r2 = r2pipe.open(infile)
        r2.cmd('aa; aar; aac')

        funcs = r2.cmdj('aflj')

        for func in funcs:

            # Generate the full zignature.
            r2.cmd('zaf ' + func['name'] + ' ' + self.generate_func_name(func['name'],infile))

            # View the zignature, get the bytes, and hash them.
            zigs = r2.cmdj('zj')
            zig_bytes = zigs[0]['bytes'] #Hacky but only a single sig can ever exist at once.
            sig_byte_hash = hashlib.md5(zig_bytes.encode()).hexdigest()

            # Only create if the function is not too short and the 
            # function hash is not stored already
            if len(zig_bytes) > 30 and sig_byte_hash not in self.temphashes:

                # Add the func+hash pair to the dict
                self.hashes[self.generate_func_name(func['name'],infile)] = sig_byte_hash

                # Update set
                self.temphashes.add(sig_byte_hash)

            # Delete all zignatures to keep continuous assurance only one exists at a time.
            r2.cmd('z-*')
            
        r2.quit()

    def rename_session_functions(self, infile):
        
        if os.path.isdir(infile):
            
            for file in self.sorted_alphanumeric(os.listdir(infile)):

                if file.endswith('.zighashes'):

                    print "Matching zig hashes for " + os.path.join(infile,file)
                    self.rename_session_functions_from_zighash_file(os.path.join(infile,file))

        elif os.path.isfile(infile) and infile.endswith('.zighashes'):

            self.rename_session_functions_from_zighash_file(infile)


    def rename_session_functions_from_zighash_file(self, infile):

        r2 = r2pipe.open()
        
        with open(infile,'r') as f:
                file_hashes = json.load(f)

        for funcname, funchash in self.hashes.iteritems():
            if funcname.startswith('fcn.') and funchash in set(file_hashes.values()):

                r2.cmd('s ' + funcname)
                r2.cmd('afn ' + self.generate_func_name(self.get_dict_key_from_value(file_hashes, funchash)))

        r2.quit()

    def check_outfile(self, outfile):

        if not outfile:
            return False

        try:
            with open(outfile,'w') as outfile:
                return True
        except IOError:
            return False

    def write_zighash_file(self, outfile):

        if not outfile.endswith('.zighashes'):
            outfile = outfile + '.zighashes'

        with open(outfile,'w') as f:
            json.dump(self.hashes, f)

    def generate_func_name(self, name, infile=None):

        if not infile:
            return name
        elif name.startswith('sym.'):
            return name
        elif name.startswith('fcn.') or name.startswith('loc.'):
            return str(os.path.basename(infile)) + '_' + name
        else:
            return name


    # Taken from:
    # https://stackoverflow.com/questions/4813061/nonalphanumeric-list-order-from-os-listdir-in-python

    def sorted_alphanumeric(self, data):
        convert = lambda text: int(text) if text.isdigit() else text.lower()
        alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ] 
        return sorted(data, key=alphanum_key)


    # Taken from:
    # https://stackoverflow.com/questions/15784590/how-can-you-print-a-key-given-a-value-in-a-dictionary-for-python/15784656

    def get_dict_key_from_value(self, dict, value):
        return [k for k,v in dict.iteritems() if v == value][0]



if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-g','--generate',action='store_true',help='Generate signatures for file or directory')
    mode.add_argument('-m','--match',action='store_true',help='Match signatures for current session')

    sigtype = parser.add_mutually_exclusive_group(required=True)
    sigtype.add_argument('-z','--zigs', action='store_true',help='Operate using r2 zignature format.')
    sigtype.add_argument('-ss','--stringset', action='store_true',help='Operate using string set matching.')

    parser.add_argument('-i','--infile', help = 'Input for generation or matching. Can be a file or directory.')
    parser.add_argument('-o','--outfile',help = 'An output file for generate mode when generating new signatures.')

    args = parser.parse_args()



    if args.generate and args.zigs and args.infile and args.outfile:

        zg = ZigHandler()
        zg.generate_hashes_from_input(args.infile, args.outfile)

    elif args.match and args.zigs and args.infile:
        
        zg = ZigHandler()
        zg.generate_hashes_from_session()
        zg.rename_session_functions(args.infile)

    else:

        print '\nCannot execute in current state\n'
        sys.exit(1)
