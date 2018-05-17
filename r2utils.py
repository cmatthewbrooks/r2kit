'''
Author: Matt Brooks, @cmatthewbrooks

DESCRIPTION:

The r2utils class is a class of various functions to be used
while coding against the radare2 r2pipes.

NOTES:


'''

import os
import json

import r2pipe

class R2Utils:

    def __init__(self):
        pass


    def get_analyzed_r2pipe_from_input(self, input_obj = None):

        if not input_obj:
            r2 = r2pipe.open()
        elif str(input_obj.__class__) == 'r2pipe.open':
            r2 = input_obj
        elif os.path.isfile(input_obj):
            r2 = r2pipe.open(input_obj)          
        else:
            return None

        try:
            r2.cmd("aflc")
        except IOError:
            raise Exception('Error: Not inside an r2 session.')


        if int(r2.cmd('aflc')) == 0:
            # If there are no functions, analyze the file
            r2.cmd("aa; aar; aac")


        return r2


####################################################################

    # These methods get different types of overall function lists

    def get_funcj_list(self, r2):

        if not str(r2.__class__) == 'r2pipe.open':
            return []

        funcj_list = []

        functions = r2.cmdj("aflj")

        if functions:

            for func in functions:

                funcj = r2.cmdj("pdfj @ " + hex(func['offset']))
                
                if funcj:
                    
                    funcj_list.append(funcj)

        return funcj_list

    def get_aflj(self, r2):

        if not str(r2.__class__) == 'r2pipe.open':
            return {}
        
        functions = r2.cmdj("aflj")

        if functions:
            return functions
        else:
            return {}


####################################################################

    # This section is all function checks of various types.

    def check_is_import_jmp_func(self, funcj):

        if (len(funcj['ops']) == 1 
            and funcj['size'] == 6 
            and funcj['ops'][0]['type'] == 'jmp'):

            return True
        else:
            return False

    def check_is_global_assignment_func(self, funcj):

        if (funcj['ops'][0]['type'] == 'mov'
            and funcj['ops'][1]['type'] == 'ret'):

            return True

        else:
            return False

    def check_is_thunk_func(self, funcj):

        if 1 < len(funcj['ops']) <= 3:
            return True
        else:
            return False

    def check_is_wrapper_func(self, funcj):

        calls = self.get_call_count_from_funcj(funcj)

        if (len(funcj['ops']) > 3 and
            len(funcj['ops']) <= 20 and
            calls == 1):
            return True
        else:
            return False

    def check_is_first_round_func(self, funcj):

        calls = self.get_call_count_from_funcj(funcj)

        if calls == 0:
            return True
        elif calls > 0:
            return False

    def check_is_utility_func(self, funcj):
        
        call_xref_count = 0

        #TODO: Fix this [0] hack
        if 'xrefs' in funcj['ops'][0]:
            for xref in funcj['ops'][0]['xrefs']:
                if xref['type'] == 'CALL':
                    call_xref_count += 1

        if call_xref_count >= 3:
            return True
        elif call_xref_count <= 2:
            return False

####################################################################

    # These methods are various small utility methods

    def get_call_count_from_funcj(self, funcj):

        count = 0

        for op in funcj['ops']:

            if 'call' in op.get('opcode','N/A'):
                count += 1        

        return count

    def parse_api_from_call(self, opcode):

        prefix = 'call dword [sym.imp'

        #The '-1' strips the right bracket off the end
        return opcode[len(prefix):len(opcode)-1]

    def get_call_from_wrapper(self, funcj):

        wrapper_call = ''

        for op in funcj['ops']:
            if 'call' in op.get('opcode','N/A'):
                wrapper_call = op.get('opcode','N/A')

        return wrapper_call

    def get_import_from_import_jmp_func(self, funcj):

        # Note: the prefix1/2 logic was added after an r2
        # update. I am unsure why some disasm has the [ bracket
        # while others do not.

        import_string = ''
        prefix1 = 'jmp dword ['
        prefix2 = 'jmp dword '

        for op in funcj['ops']:

            import_string = op.get('disasm','N/A')

            if prefix1 in op.get('disasm','N/A'):
                return import_string[len(prefix1):len(import_string)-1]

            elif prefix2 in op.get('disasm','N/A'):
                return import_string[len(prefix2):len(import_string)]


if __name__ == "__main__":
    test()