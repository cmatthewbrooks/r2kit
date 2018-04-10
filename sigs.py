
# Author: Matt Brooks, @cmatthewbrooks


import os,sys
import argparse
import hashlib
import re
import json
import base64

import r2pipe
import r2utils as r2u



r2utils = r2u.R2Utils()



class Matcher:
    '''

    The Matcher class is used to match signature hashes and rename functions
    during an active r2 session. It uses a Generator and generates the correct
    sigtype based on the extension of the signature file being used.

    '''

    def __init__(self, location, r2 = None):

        self.r2 = r2utils.get_analyzed_r2pipe_from_input(r2)
        self.gen = Generator(self.r2)
        self.file_list = get_file_list_from_location(location)

    def match(self):
            
        for file in self.file_list:

            print 'Matching from ' + file + '...'

            sigtype = os.path.splitext(file)[1].lower()[1:]

            self.gen.generate(sigtype)


            with open(file,'r') as f:
                file_hashes = json.load(f)

            
            for funcname, funchash in self.gen.hashes.iteritems():

                if (funcname.startswith('fcn.') and 
                    funchash in set(file_hashes.values())):

                    self.r2.cmd('s ' + funcname)
                    self.r2.cmd(
                        'afn ' + self.get_dict_key_from_value(
                            file_hashes, funchash
                    ))

            self.gen.clear_hashes()


        self.r2.quit()


    # Taken from:
    # https://stackoverflow.com/questions/15784590/
    # how-can-you-print-a-key-given-a-value-in-a-dictionary-for-python/15784656

    def get_dict_key_from_value(self, dict, value):
        return [k for k,v in dict.iteritems() if v == value][0]


class Maker:
    '''

    The Maker class is used to make signatures. It uses a Generator and
    generates signatures of a given sigtype passed as an argument.

    '''

    def __init__(self, sigtype, location, outfile):

        self.sigtype = sigtype
        self.file_list = get_file_list_from_location(location)
        self.outfile = outfile
        self.hashes = {}

    def sigmake(self):

        if not self.validate_outfile(self.outfile):
            raise IOError('Cannot create outfile ' + outfile)
        

        for file in self.file_list:

            print 'Making ' + file + '...'

            r2 = r2utils.get_analyzed_r2pipe_from_input(file)

            g = Generator(r2)
            g.generate(self.sigtype)

            for k,v in g.hashes.iteritems():
                if v not in self.hashes.values():
                    self.hashes[self.generate_func_name(k, file)] = v

            r2.quit()


        self.write_hash_file(self.outfile, self.sigtype)

    def generate_func_name(self, name, location):

        if name.startswith('sym.'):
            return name
        elif name.startswith('fcn.') or name.startswith('loc.'):
            return str(os.path.basename(location)) + '_' + name
        else:
            return name

    def write_hash_file(self, outfile, sigtype):

        extension = '.' + sigtype

        if (outfile.count('.') == 1 and
            outfile.endswith(extension)):

            pass

        elif outfile.count('.') == 0:

            outfile = outfile + extension

        elif ('.' in outfile and 
            not outfile.endswith(extension)):

            outfile = outfile.split('.')[0] + extension

        with open(outfile,'w') as f:
            json.dump(self.hashes, f)

    def validate_outfile(self, outfile):

        try:
            with open(outfile,'w') as outfile:
                return True

        except IOError:
            return False



class Generator(object):
    '''

    The Generator class generates function hashes of a given type. Each
    type is implemented as a subclass where the subclass requirements are
    a class attribute for the signature and a single method to return the
    generated hashes as a Python dictionary.

    '''
    
    def __init__(self, r2):
            
        self.valid_generators = self.initialize_generators()

        if str(r2.__class__) != 'r2pipe.open':
            raise ValueError(r2 + 'is not a valid r2pipe.')

        self.r2 = r2utils.get_analyzed_r2pipe_from_input(r2)

        self.hashes = {}

    @staticmethod
    def initialize_generators():
        
        generators = dict()

        for cls in Generator.__subclasses__():
            generators[cls.sigtype] = cls

        return generators

    def generate(self, sigtype):

        if sigtype not in self.valid_generators:
            raise ValueError(sigtype + ' is not a valid sigtype.')

        cls = self.valid_generators[sigtype](self.r2)
        self.hashes.update(cls.generate_hashes())

    def clear_hashes(self):

        self.hashes = {}


class ZigGenerator(Generator):

    sigtype = 'zighash'

    def __init__(self, r2):

        Generator.__init__(self, r2)


    def generate_hashes(self):

        hashes = {}
        temphashes = set()

        funcs = self.r2.cmdj('aflj')

        for func in funcs:

            # Generate the full zignature.
            self.r2.cmd('zaf ' + func['name'] + ' ' + func['name'])

            # View the zignature, get the bytes, and hash them.
            zigs = self.r2.cmdj('zj')

            # Hacky but only a single sig can ever exist at once.
            zig_bytes = zigs[0]['bytes'] 

            sig_byte_hash = hashlib.md5(zig_bytes.encode()).hexdigest()

            # Only create if the function is not too short and the 
            # function hash is not stored already
            if len(zig_bytes) > 30 and sig_byte_hash not in temphashes:

                # Add the func+hash pair to the dict
                hashes[func['name']] = (
                    sig_byte_hash
                )

                # Update set
                temphashes.add(sig_byte_hash)

            # Delete all zignatures to keep continuous 
            # assurance only one exists at a time.
            self.r2.cmd('z-*')
            
        return hashes



class StringSetGenerator(Generator):

    sigtype = 'stringsethash'

    def __init__(self, r2):

        Generator.__init__(self, r2)
        

    def generate_hashes(self):

        hashes = {}
        temphashes = set()
        string_sets = {}

        strings = self.r2.cmdj("izzj")

        # First, get the strings and for each string, make sure it is
        # ascii or wide.
        if strings:
            for string in strings['strings']:
                if string['type'] == 'ascii' or string['type'] == 'utf8':

                    # Next, get the cross references to the string.
                    xrefto = self.r2.cmdj("axtj " + str(string['vaddr']))
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

            if stringsethash not in temphashes:

                temphashes.add(stringsethash)
                hashes[func] = (
                    stringsethash
                )


        return hashes




def get_file_list_from_location(location):
    '''
    This method is meant to abstract a location so that whether
    a file or directory is passed, a for loop over the file_list
    can be used. This should reduce code as I've had to use this
    pattern multiple times.
    '''

    file_list = []

    if os.path.isdir(location):
        
        for file in sorted_alphanumeric(os.listdir(location)):

            file_list.append(os.path.join(location, file))

    elif os.path.isfile(location):

            file_list.append(location)

    return file_list

# Taken from:
# https://stackoverflow.com/questions/4813061/
# nonalphanumeric-list-order-from-os-listdir-in-python

def sorted_alphanumeric(data):
    convert = lambda text: int(text) if text.isdigit() else text.lower()

    alphanum_key = lambda key: [ 
        convert(c) for c in re.split('([0-9]+)', key) 
    ]

    return sorted(data, key=alphanum_key)


def usage():

    print '\n' + sys.argv[0] + ' - make or match hashed function signatures.'

    print '''

    DESC:

        This utility allows a user to make or match hashed function
        signatures. Currently supported signature types include:

            - Hashes of r2's native zignature format
            - Hashes of function string set references

    MAKING:

        -mk - flag specifying 'make' mode

        -t - sigtype to make

        -l - location of input files (can be file or directory)

        -o - output signature file

    MATCHING:

        -mt - flag specifying 'match' mode

        -l - location of signature files to match (can be file or directory)



    '''


if __name__ == '__main__':

    if len(sys.argv) == 1:
        usage()
        sys.exit(1)

    # Do all the arg stuff.

    parser = argparse.ArgumentParser()

    mode = parser.add_mutually_exclusive_group(required=True)

    mode.add_argument('-mk','--make',
        action='store_true',help='Make signatures for file or directory')
    mode.add_argument('-mt','--match',
        action='store_true',help='Match signatures for current session')


    parser.add_argument('-t','--sigtype',
        help = 'The type of function hashes to make.')

    parser.add_argument('-l','--location', 
        help = 'Location for making or matching (can be file or directory).')

    parser.add_argument('-o','--outfile',
        help = 'An output file for making new signatures.')

    args = parser.parse_args()


    # Execute according to args.

    if args.make and args.sigtype and args.location and args.outfile:

        maker = Maker(args.sigtype, args.location, args.outfile)
        maker.sigmake()

    elif args.match and args.location:

        matcher = Matcher(args.location)
        matcher.match()

    else:

        raise RuntimeError('Cannot execute in current state.')
