'''
Author: Matt Brooks, @cmatthewbrooks



DESCRIPTION:

The r2utils class is a class of various functions to be used
while coding against the radare2 r2pipes.

NOTES:

If you're reading this class file, you may find the following points
of information helpful:

- For the initial r2pipe analysis command, others may prefer the
  standard 'aaa' for analysis. The final step of that analysis is
  an automatic renaming I didn't enjoy. The 'aa; aac; aar' chain
  used throughout this file is all of the 'aaa' analysis sans the
  renaming.

'''

import os
import json

import r2pipe

class r2utils:

    def __init__(self):
        pass

####################################################################

    def get_funcj_list_from_file(self, file):

        funcj_list = []

        r2 = r2pipe.open(file) 

        func_count = r2.cmd('aflc')

        if func_count == 0:
            # If there are no functions, analyze the file
            r2.cmd("aa; aar; aac")

        elif func_count > 0:

            functions = r2.cmdj("aflj")

            if functions:

                for func in functions:

                    funcj = r2.cmdj("pdfj @ " + hex(f['offset']))
                    
                    if funcj:
                        
                        funcj_list.append(funcj)

        r2.quit()
        return funcj_list

    def get_aflj_from_file(self, file):

        r2 = r2pipe.open(file) 

        func_count = r2.cmd('aflc')

        if func_count == 0:
            # If there are no functions, analyze the file
            r2.cmd("aa; aar; aac")

        elif func_count > 0:
        
            functions = r2.cmdj("aflj")

            if functions:
                r2.quit()
                return functions
            else:
                r2.quit()
                return {}

    def get_funcj_list_from_session(self):

        funcj_list = []

        r2 = r2pipe.open(file) 

        func_count = r2.cmd('aflc')

        if func_count == 0:
            # If there are no functions, analyze the file
            r2.cmd("aa; aar; aac")

        elif func_count > 0:

            functions = r2.cmdj("aflj")

            if functions:
                
                for f in functions:

                    func = r2.cmdj("pdfj @ " + hex(f['offset']))

                    if func:
                        
                        funcj_list.append(func)

            r2.quit()
            return funcj_list

    def get_aflj_from_session(self):

        r2 = r2pipe.open() 

        func_count = r2.cmd('aflc')

        if func_count == 0:
            # If there are no functions, analyze the file
            r2.cmd("aa; aar; aac")

        elif func_count > 0:
        
            functions = r2.cmdj("aflj")

            if functions:
                r2.quit()
                return functions
            else:
                r2.quit()
                return {}


####################################################################

    '''
    SECTION: function checks

    This section includes checks for various function types.
    '''

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
        '''
        INPUT: An r2 json object returned by the cmd:
            pdfj @ <offset>

        DESCRIPTION:

        Note - this is theoritical/experimental. The idea is that 
        functions with fewer than 3 instructions can be skipped 
        for most function analysis questions. They can be thunk
        functions or global variable assignments.

        RETURN: True if the function is thunk; False
        by default.
        '''

        if 1 < len(funcj['ops']) <= 3:
            return True
        else:
            return False

    def check_is_wrapper_func(self, funcj):
        '''
        INPUT: An r2 json object returned by the cmd:
            pdfj @ <offset>

        DESCRIPTION:

        In this implementation, a "wrapper" is a disassembled
        function designed simply to set up the stack frame
        before calling another function. Typically, wrappers
        consist of a single basic block of between 4 and 20
        instructions with only a single call.

        RETURN: True if the function is a wrapper; False
        by default.       
        '''

        calls = self.get_call_count_from_funcj(funcj)

        if (len(funcj['ops']) > 3 and
            len(funcj['ops']) <= 20 and
            calls == 1):
            return True
        else:
            return False


    def check_is_first_round_func(self, funcj):
        '''
        INPUT: An r2 json object returned by the cmd:
            pdfj @ <offset>

        DESCRIPTION:

        In this implementation, "first round" functions
        are defined as developer-written functions that 
        do not contain any call instructions. First-round 
        functions are easy to start with when naming unknown 
        functions.

        NOTE: Before calling this function, make sure to
        weed out libs, thunks, etc using check_is_too_short_func.

        RETURN: True if the function is first-round; False
        by default.
        '''

        if not self.check_is_analysis_func(funcj):
            return False

        calls = self.get_call_count_from_funcj(funcj)

        if calls == 0:
            return True
        elif calls > 0:
            return False

    def check_is_utility_func(self, funcj):
        '''
        INPUT: An r2 json object returned by the cmd:
            pdfj @ <offset>

        DESCRIPTION:

        In this implementation, "utility" functions are
        heavily called.

        NOTE: Before calling this function, make sure to
        weed out libs, thunks, etc using 
        check_is_analysis_func.

        RETURN: True if the function is utility; False by
        default.
        '''

        if not self.check_is_analysis_func(funcj):
            return False
        
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

    def check_is_analysis_func(self, funcj):
        '''
        INPUT: An r2 json object returned by the cmd:
            pdfj @ <offset>

        DESCRIPTION:


        RETURN: True if the function is worth analying;
        False if the function is basic.
        '''

        if self.check_is_import_jmp_func(funcj):
            return False
        elif self.check_is_thunk_func(funcj):
            return False
        elif self.check_is_wrapper_func(funcj):
            return False
        else:
            return True



####################################################################

    '''
    SECTION: utilities

    These are small reusable functions with multiple use cases.
    '''

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

        import_string = ''
        prefix = 'jmp dword ['

        for op in funcj['ops']:
            import_string = op.get('opcode','N/A')

        return import_string[len(prefix):len(import_string)-1]


####################################################################

    '''
    SECTION: tests

    This is the test function for various testing.
    '''

def test():    
    pass


if __name__ == "__main__":
    test()