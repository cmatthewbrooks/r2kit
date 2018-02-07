
import os,sys
import argparse
import json

import r2pipe 

class YaraRule:

    def __init__(self):
        self.AUTHOR = "Matt Brooks, @cmatthewbrooks"

    def create(self,name,author):

        rule = self.create_rule(name,author)
        print rule

    def create_rule(self,name,author):

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

        if name:
            return name.replace(' ','')
        else:
            return 'unnamed'

    def make_author_name(self,author=None):

        if self.AUTHOR:
            return self.AUTHOR
        elif author:
            return author
        else:
            return ''

    def get_file_name(self):

        r2 = r2pipe.open()
        info = r2.cmd('ij')
        r2.quit()

        if info:
            infoj = json.loads(info)
            return infoj['core']['file']
        
        else:
            return ''

    def format_comment_instructions(self):

        comment_instructions = ''

        r2 = r2pipe.open()
        func = r2.cmd('pdfj')
        r2.quit()

        if func:
            funcj = json.loads(func)
            
            for op in funcj['ops']:
                comment_instructions += '// ' + op['bytes']
                comment_instructions += ' ' * (16 - len(op['bytes']))
                comment_instructions +=  op['opcode'] + '\r\n' + ' ' * 8


        return comment_instructions


    def get_func_yara_opcodes(self):
        
        r2 = r2pipe.open()
        r2.cmd('z-*')
        r2.cmd('zaf')
        sig = r2.cmd('zj')
        r2.quit()

        if sig:
            
            sigj = json.loads(sig)
            return sigj[0]['bytes'].replace('.','?')

        else:
            return ''

    def format_rule_opcodes(self, opcode_string):

        formatted_opcode_string = ''
        odd = True
        even = False
        line_char_count = 0 #An appearance of 8 opcodes would be 24 characters

        for char in opcode_string:

            if odd:

                formatted_opcode_string += char
                line_char_count += 1
                odd = False
                even = True

            elif even:

                if line_char_count == 22: #add the final char then add the new-line
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