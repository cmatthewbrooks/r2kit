'''
Author: Matt Brooks, @cmatthewbrooks

DESCRIPTION:

The functoyara.py script will output an opcode-based YARA
signature from the current function of the r2 session.

ARGS:

This script can take up to two optional arguments and attempts
to use sane defaults if those arguments are not passed.

-n (--name): This will be the name of the signature. If this
is not passed in at runtime, the name will simply be
"unnamed_rule".

-a (--author): This will be the authorship string of the
signature. 

    ^^ Note there is also a constant hardcoded into the
    YaraRule class. If that constant value is set, that value
    will override the argument under the assumption the user
    does not want to keep setting their most commonly used
    authorship string.

NOTES:

- This script can only be run within an r2 session. It does
not stand-alone.

- Currently, this script uses the r2 signature-generation
capability to determine which bytes should exist and which
bytes should be wild-carded.

TODO:

- Get file hashes quickly from within an r2 shell to add
  as rule meta??

- Examine a better way to create the byte string?

- Test x64 or .NET files.

'''


import os,sys
import argparse
import json

import r2pipe 

class YaraRule:

    def __init__(self):
        # Again, note that setting this value overrides any
        # -a args passed at run-time.
        self.AUTHOR = "Matt Brooks, @cmatthewbrooks"

    def create(self,name,author):
        # This is the externally-facing func to be called from
        # outside the class.
        rule = self.create_rule(name,author)
        print rule

    ##########################################################

    def create_rule(self,name,author):

        # While parts of this command could have been merged for
        # fewer lines, readability was most important to me so
        # others reading code could understand where each part
        # of the signature was being built.

        rule = 'rule ' + self.make_rule_name(name) + ' {\r\n'
        rule += '\r\n'
        rule += '    meta:\r\n'
        rule += '\r\n'
        rule += '        author = "' + self.make_author_name(author) + '"\r\n'
        rule += '        file = "' + self.get_file_name() + '"\r\n'
        rule += '\r\n'
        rule += '    strings:\r\n'
        rule += '\r\n'
        rule += '        ' + self.format_comment_instructions()
        rule += '\r\n'
        rule += '        $func = {\r\n\r\n'
        rule += '            ' + self.format_rule_opcodes(self.get_func_yara_opcodes()) + '\r\n\r\n'
        rule += '                }\r\n'
        rule += '\r\n'
        rule += '    condition:\r\n'
        rule += '\r\n'
        rule += '        $func\r\n'
        rule += '\r\n'
        rule += '}'

        return rule

    def make_rule_name(self,name):

        # Just parse the arg or return a default.

        if name:
            return name.replace(' ','')
        else:
            return 'unnamed_rule'

    def make_author_name(self,author=None):

        # Check for constant, parse the arg, or
        # return a default.

        if self.AUTHOR:
            return self.AUTHOR
        elif author:
            return author
        else:
            return ''

    def get_file_name(self):

        # Grab the filename over r2pipe.

        r2 = r2pipe.open()
        infoj = r2.cmdj('ij')
        r2.quit()

        if infoj:
            return infoj['core']['file']
        
        else:
            return ''

    def format_comment_instructions(self):

        # This will make sure the function instructions
        # are also saved within the rule for future
        # reference.

        comment_instructions = ''

        r2 = r2pipe.open()
        funcj = r2.cmdj('pdfj')
        r2.quit()

        if funcj:
            
            for op in funcj['ops']:

                # This was hanus to read on one line so I split it up.
                comment_instructions += '// ' + op.get('bytes','')
                comment_instructions += ' ' * (16 - len(op['bytes']))
                comment_instructions +=  op['opcode'] + '\r\n' + ' ' * 8


        return comment_instructions


    def get_func_yara_opcodes(self):

        # As mentioned above, the bytes for the printed signature
        # come from r2's zignatures functionality.
        
        r2 = r2pipe.open()
        r2.cmd('z-*') #This removes existing signatures to achieve confidence only one exists.
        r2.cmd('zaf')
        sigj = r2.cmdj('zj')
        r2.quit()

        if sigj:

            #r2 uses '.' whereas YARA uses '?' for wildcards.
            return sigj[0]['bytes'].replace('.','?')

        else:
            return ''

    def format_rule_opcodes(self, opcode_string):

        formatted_opcode_string = ''
        odd = True
        even = False
        line_char_count = 0 #An appearance of 8 opcodes would be 24 characters

        '''
        TODO: I'm sure there is a simpler, more pythonic way to do this

                00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
            
                                   becomes
                            
                            00 11 22 33 44 55 66 77
                            88 99 AA BB CC DD EE FF
        '''

        for char in opcode_string:

            if odd:

                formatted_opcode_string += char
                line_char_count += 1
                odd = False
                even = True

            elif even:

                if line_char_count == 22:
                    formatted_opcode_string += char + '\r\n' + ' ' * 12
                    line_char_count = 0

                else:
                    formatted_opcode_string += char + ' '
                    line_char_count += 2

                odd = True
                even = False

        return formatted_opcode_string
        

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser()

    parser.add_argument('-n','--name',help='The name for the rule.')
    parser.add_argument('-a','--author',help='The author string. Note: the constant AUTHOR overrides this arg.')

    args = parser.parse_args()

    rule = YaraRule()
    rule.create(args.name,args.author)