
# Author: Matt Brooks, @cmatthewbrooks


import os,sys
import argparse
import json

import r2pipe 


class YaraRule:

    def __init__(self, r2):
        # Again, note that setting this value overrides any
        # -a args passed at run-time.
        self.AUTHOR = "Matt Brooks, @cmatthewbrooks"
        self.r2 = r2

    def print_rule(self,name,author):
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

        infoj = self.r2.cmdj('ij')

        if infoj:
            return infoj['core']['file']
        
        else:
            return ''

    def format_comment_instructions(self):

        # This will make sure the function instructions
        # are also saved within the rule for future
        # reference.

        comment_instructions = ''

        funcj = self.r2.cmdj('pdfj')

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
        
        self.r2.cmd('z-*') #This removes existing signatures so only one exists.
        self.r2.cmd('zaf')
        sigj = self.r2.cmdj('zj')

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


def usage():

    print '\n' + sys.argv[0] + ' - generate YARA signatures from functions.'

    print '''

    DESCRIPTION:

        This utility allows a user to generate YARA signatures for a given
        function.

        It is assumed this script is being invoked from within an active
        r2 session. It is also assumed the session offset is the start of
        the target function.

    EXAMPLES:

        >> #!pipe python functoyara.py    

        >> #!pipe python functoyara.py -n test_yara_rule -a "Matt Brooks"

    ARGS:

        -n - a name for the rule; a default will be used if this is not
             provided

        -a - authorship for the meta field; this can be overridden by
             setting the instance attribute for the YaraRule class


    '''



if __name__ == '__main__':


    if len(sys.argv) == 1:
        usage()
        sys.exit(1)
    
    parser = argparse.ArgumentParser()

    parser.add_argument('-n','--name',help='The name for the rule.')
    parser.add_argument('-a','--author',
        help='The author string. Note: the constant AUTHOR overrides this arg.')

    args = parser.parse_args()

    r2 = r2pipe.open()

    try:

        if int(r2.cmd("aflc")) == 0:

            raise Exception(
                "The file has not been analyzed. Run aaa (or similar)."
            )

    except IOError:
        print "\n\tError: Not inside an r2 session.\n"
        sys.exit(1)

    rule = YaraRule(r2)
    rule.print_rule(args.name,args.author)

    r2.quit()