'''
Author: Matt Brooks, @cmatthewbrooks

DESCRIPTION:

The sigs.py script creates Python dicts of func name/hash
pairs for different types of intake patterns. Currently supported
intake patterns include:

 - The r2 native zignature format.
 - Function reference strings stored in list form.

These intake patterns are then hashed for smaller storage size and
performance gains on matching.

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

- Implement dynamic instantiation based on file extension
  in the Renamer class' rename_recognized_code method.


'''

import os,sys
import argparse
import hashlib
import re
import json
import base64

import r2pipe

class Renamer:
    '''

    The Renamer class is meant to be called from outside this
    file as a way for the SessionStarter script to easily rename
    all possible signature types in a directory.

    '''
    def __init__(self):
        pass

    def rename_recognized_code(self, infile):

        # TODO: Implement dynamic instantiation based on file extension

        if os.path.isdir(infile):
            
            for file in os.listdir(infile):
                
                if file.endswith('.zighashes'):

                    zh = ZigHandler()
                    zh.generate_hashes_from_session()
                    zh.rename_session_functions(os.path.join(infile, file))

                elif file.endswith('.stringsethashes'):

                    ssh = StringSetHandler()
                    ssh.generate_hashes_from_session()
                    ssh.rename_session_functions(os.path.join(infile, file))

        elif os.path.isfile(infile):
            
            if infile.endswith('.zighashes'):

                zh = ZigHandler()
                zh.generate_hashes_from_session()
                zh.rename_session_functions(infile)

            elif infile.endswith('.stringsethashes'):

                ssh = StringSetHandler()
                ssh.generate_hashes_from_session()
                ssh.rename_session_functions(infile)

class Handler:
    '''

    The Handler class is the parent class to handle sig hash
    generation and matching. All child classes simply need to
    define an extension for their filetype and implement the
    generate_hashes method.

    '''
    def __init__(self):

        self.hashes = {}
        self.temphashes = set()

        self.EXTENSION = ''

    def generate_hashes(self):
        
        #This is overridden by child classes
        pass

    def generate_hashes_from_session(self):

        self.generate_hashes()

    def generate_hashes_from_input(self, infile, outfile):

        if os.path.isdir(infile) and self.check_outfile(outfile):

            self.generate_hashes_from_dir(infile)
            self.write_hash_file(outfile)
        
        elif os.path.isfile(infile) and self.check_outfile(outfile):
        
            self.generate_hashes(infile)
            self.write_hash_file(outfile)
        
        else:
        
            print "\nCannot create from input.\n"
            sys.exit(1)

    def generate_hashes_from_dir(self, directory):
        
        for file in self.sorted_alphanumeric(os.listdir(directory)):

            print "Generating hashes for " + os.path.join(directory, file)
            self.generate_hashes(os.path.join(directory, file))

    def rename_session_functions(self, infile):
        
        if os.path.isdir(infile):
            
            for file in self.sorted_alphanumeric(os.listdir(infile)):

                if file.endswith(self.EXTENSION):

                    self.rename_session_functions_from_hash_file(
                        os.path.join(infile,file)
                    )

        elif os.path.isfile(infile) and infile.endswith(self.EXTENSION):

            self.rename_session_functions_from_hash_file(infile)

    def rename_session_functions_from_hash_file(self, infile):
        
        r2 = r2pipe.open()
        
        with open(infile,'r') as f:
                file_hashes = json.load(f)

        for funcname, funchash in self.hashes.iteritems():

            if (funcname.startswith('fcn.') and 
                funchash in set(file_hashes.values())):

                r2.cmd('s ' + funcname)
                r2.cmd('afn ' + self.generate_func_name(
                    self.get_dict_key_from_value(file_hashes, funchash))
                )

        r2.quit()

    def write_hash_file(self, outfile):

        if (outfile.count('.') == 1 and
            outfile.endswith(self.EXTENSION)):

            pass

        elif outfile.count('.') == 0:

            outfile = outfile + self.EXTENSION

        elif ('.' in outfile and 
            not outfile.endswith(self.EXTENSION)):

            outfile = outfile.split('.')[0] + self.EXTENSION

        with open(outfile,'w') as f:
            json.dump(self.hashes, f)

    def check_outfile(self, outfile):

        if not outfile:
            return False

        try:
            with open(outfile,'w') as outfile:
                return True

        except IOError:
            return False

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
    # https://stackoverflow.com/questions/4813061/
    # nonalphanumeric-list-order-from-os-listdir-in-python

    def sorted_alphanumeric(self, data):
        convert = lambda text: int(text) if text.isdigit() else text.lower()
        alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ]
        return sorted(data, key=alphanum_key)

    # Taken from:
    # https://stackoverflow.com/questions/15784590/
    # how-can-you-print-a-key-given-a-value-in-a-dictionary-for-python/15784656

    def get_dict_key_from_value(self, dict, value):
        return [k for k,v in dict.iteritems() if v == value][0]


class ZigHandler(Handler):
    '''

    The ZigHandler class inherits from the Handler class. This child
    handler generates hashes from byte sequences returned by a native
    r2 zignature.

    '''

    def __init__(self):

        Handler.__init__(self)
        self.EXTENSION = '.zighashes'

    def generate_hashes(self, infile=None):
        
        r2 = r2pipe.open(infile)
        
        func_count = r2.cmd('aflc')

        if int(func_count) == 0:
            
            # If there are no functions, analyze the file
            r2.cmd("aa; aar; aac")

        funcs = r2.cmdj('aflj')

        for func in funcs:

            # Generate the full zignature.
            r2.cmd('zaf ' + func['name'] + ' ' + self.generate_func_name(
                func['name'],infile)
            )

            # View the zignature, get the bytes, and hash them.
            zigs = r2.cmdj('zj')

            # Hacky but only a single sig can ever exist at once.
            zig_bytes = zigs[0]['bytes'] 

            sig_byte_hash = hashlib.md5(zig_bytes.encode()).hexdigest()

            # Only create if the function is not too short and the 
            # function hash is not stored already
            if len(zig_bytes) > 30 and sig_byte_hash not in self.temphashes:

                # Add the func+hash pair to the dict
                self.hashes[self.generate_func_name(func['name'],infile)] = (
                    sig_byte_hash
                )

                # Update set
                self.temphashes.add(sig_byte_hash)

            # Delete all zignatures to keep continuous 
            # assurance only one exists at a time.
            r2.cmd('z-*')
            
        r2.quit()



class StringSetHandler(Handler):
    '''

    The StringSetHandler class interits from the Handler class. This child
    handler generates hashes from lists of strings referenced in a given
    function.

    '''

    def __init__(self):
        
        Handler.__init__(self)
        self.EXTENSION = '.stringsethashes'

    def generate_hashes(self, infile=None):

        string_sets = {}

        if not infile:
            infile = ''

        r2 = r2pipe.open(infile) 
        func_count = r2.cmd('aflc')

        if int(func_count) == 0:
            
            # If there are no functions, analyze the file
            r2.cmd("aa; aar; aac")
        

        strings = r2.cmdj("izzj")

        # First, get the strings and for each string, make sure it is
        # ascii or wide.
        if strings:
            for string in strings['strings']:
                if string['type'] == 'ascii' or string['type'] == 'utf8':

                    # Next, get the cross references to the string.
                    xrefto = r2.cmdj("axtj " + str(string['vaddr']))
                    if xrefto:
                        for xref in xrefto:

                            # If the xref comes from a function, either add it
                            # to the list or add a new dictionary item.
                            if ('fcn_name' in xref and 
                                len(base64.b64decode(string['string'])) >= 10):

                                if xref['fcn_name'] in string_sets:

                                    string_sets[xref['fcn_name']].append(
                                        base64.b64decode(string['string'])
                                    )

                                elif xref['fcn_name'] not in string_sets:

                                    string_sets[xref['fcn_name']] = (
                                        [base64.b64decode(string['string'])]
                                    )


        # After generating a dict of function name keys matched to referenced
        # strings in a list as the value, hash the distinct values and handle
        # collisions.
        for func, stringset in string_sets.iteritems():

            stringsethash = hashlib.md5(''.join(stringset)).hexdigest()

            if stringsethash not in self.temphashes:

                self.temphashes.add(stringsethash)
                self.hashes[self.generate_func_name(func, infile)] = (
                    stringsethash
                )

        r2.quit()


if __name__ == '__main__':

    # Do all the arg stuff.

    parser = argparse.ArgumentParser()

    mode = parser.add_mutually_exclusive_group(required=True)

    mode.add_argument('-g','--generate',
        action='store_true',help='Generate signatures for file or directory')
    mode.add_argument('-m','--match',
        action='store_true',help='Match signatures for current session')

    sigtype = parser.add_mutually_exclusive_group(required=True)

    sigtype.add_argument('-z','--zigs', 
        action='store_true',help='Operate using r2 zignature format.')
    sigtype.add_argument('-ss','--stringset', 
        action='store_true',help='Operate using string set matching.')

    parser.add_argument('-i','--infile', 
        help = 'Input for generation or matching. Can be a file or directory.')
    parser.add_argument('-o','--outfile',
        help = 'An output file for generate mode when generating new signatures.')

    args = parser.parse_args()


    # Execute according to args.

    if args.generate and args.zigs and args.infile and args.outfile:

        zh = ZigHandler()
        zh.generate_hashes_from_input(args.infile, args.outfile)

    elif args.match and args.zigs and args.infile:
        
        zh = ZigHandler()
        zh.generate_hashes_from_session()
        zh.rename_session_functions(args.infile)

    elif args.generate and args.stringset and args.infile and args.outfile:

        ssh = StringSetHandler()
        ssh.generate_hashes_from_input(args.infile, args.outfile)

    elif args.match and args.stringset and args.infile:

        ssh = StringSetHandler()
        ssh.generate_hashes_from_session()
        ssh.rename_session_functions(args.infile)

    else:

        print '\nCannot execute in current state\n'
        sys.exit(1)
