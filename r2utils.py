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

import r2pipe

import os
import json



GADGETS = [

{'name': 'enumerate_processes', 'api_chain': ['CreateToolhelp32Snapshot','Process32First','Process32Next']},
{'name': 'search_files', 'api_chain': ['FindFirstFile','FindNextFile','FindClose']},
{'name': 'query_regkey', 'api_chain': ['RegOpenKey','RegQueryValue','RegCloseKey']},
{'name': 'access_resources', 'api_chain': ['FindResource','LoadResource','LockResource']}

]



class r2utils:

    def __init__(self):
        pass

####################################################################

    def get_funcj_list_from_file(self, file):

        funcj_list = []

        r2 = r2pipe.open(file) 
        r2.cmd("aa; aar; aac")
        functions = r2.cmd("aflj")

        if functions:
            functionsj = json.loads(functions)
            for f in functionsj:

                func = r2.cmd("pdfj @ " + hex(f['offset']))
                if func:
                    
                    funcj = json.loads(func)
                    funcj_list.append(funcj)

        r2.quit()
        return funcj_list

    def get_aflj_from_file(self, file):

        r2 = r2pipe.open(file) 
        r2.cmd("aa; aar; aac")
        functions = r2.cmd("aflj")

        if functions:
            r2.quit()
            return json.loads(functions)
        else:
            r2.quit()
            return {}

    def get_funcj_list_from_session(self):

        funcj_list = []

        r2 = r2pipe.open() 
        r2.cmd("aa; aar; aac")
        functions = r2.cmd("aflj")

        if functions:
            functionsj = json.loads(functions)
            for f in functionsj:

                func = r2.cmd("pdfj @ " + hex(f['offset']))
                if func:
                    
                    funcj = json.loads(func)
                    funcj_list.append(funcj)

        r2.quit()
        return funcj_list

    def get_aflj_from_session(self):

        r2 = r2pipe.open() 
        r2.cmd("aa; aar; aac")
        functions = r2.cmd("aflj")

        if functions:
            r2.quit()
            return json.loads(functions)
        else:
            r2.quit()
            return {}

####################################################################

    def classify_function(self, func):

        pass

    def classify_function_complexity(self, funcj):

        #TODO: Add basic block complexity

        if len(funcj['ops']) > 50:
            return 'complex'
        else:
            return 'simple'

    def classify_call(self, opcode):

        if 'call fcn.' in opcode:
            return 'direct'
        elif 'call loc.' in opcode:
            return 'dynamic'
        elif any(reg in opcode for reg in 
            ['eax','ebx','ecx','edx','esi','edi','esp','ebp']):
            return 'register'
        elif 'call dword [sym.imp.' in opcode:
            return 'win_api'


####################################################################

    def check_call_chain_is_api_only(self, call_chain):
        
        for call in call_chain:
            if not self.classify_call(call) == 'win_api':
                return False

        return True

    def check_call_chain_is_direct_only(self, call_chain):
        
        for call in call_chain:
            if not self.classify_call(call) == 'direct':
                return False

        return True



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

    def check_is_direct_control_flow_func(self, funcj):
        '''

        '''
        call_chain = self.get_raw_call_chain_from_funcj(funcj)

        return self.check_call_chain_is_direct_only(call_chain)

    def check_is_win_api_control_flow_func(self, funcj):
        '''

        '''
        call_chain = self.get_raw_call_chain_from_funcj(funcj)

        return self.check_call_chain_is_api_only(call_chain)



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

    def get_direct_call_count_from_funcj(self, funcj):

        count = 0

        for op in funcj['ops']:

            if ('call' in op.get('opcode','N/A') and
                self.classify_call(op.get('opcode','N/A'))) == 'direct':

                count += 1        

        return count

    def get_win_api_call_count_from_funcj(self, funcj):

        count = 0

        for op in funcj['ops']:

            if ('call' in op.get('opcode','N/A') and
                self.classify_call(op.get('opcode','N/A'))) == 'win_api':

                count += 1        

        return count

    def parse_api_from_call(self, opcode):

        prefix = 'call dword [sym.imp'

        #The '-1' strips the right bracket off the end
        return opcode[len(prefix):len(opcode)-1]

    def parse_clean_api_from_r2_api_cat(self, api):

        if any(api.endswith(char) for char in ['A','W']):
            api = api[:len(api)-1]
        elif any(api.endswith(suffix) for suffix in ['ExA','ExW']):
            api = api[:len(api)-3]

        return str(api.rpartition('_')[2])

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



    def get_raw_call_chain_from_funcj(self, funcj):

        call_chain = []

        for op in funcj['ops']:
            if 'call' in op.get('opcode','N/A'):
                call_chain.append(op.get('opcode','N/A'))

        return call_chain

    def get_clean_call_chain_from_funcj(self, funcj):

        call_chain = self.get_raw_call_chain_from_funcj(funcj)
        clean_call_chain = []

        for call in call_chain:

            if self.classify_call(call) == 'win_api':
                clean_call_chain.append(
                    self.parse_clean_api_from_r2_api_cat(
                    self.parse_api_from_call(call)    
                    ))
            else:
                clean_call_chain.append(self.classify_call(call))

        return clean_call_chain

    def find_gadgets_in_clean_call_chain(self, call_chain):

        gadgets = []

        for gadget in GADGETS:
            if set(gadget['api_chain']).issubset(set(call_chain)):
                gadgets.append(gadget['name'])
                gadgets.append(call_chain)
        
        return gadgets


####################################################################

    '''
    SECTION: tests

    This is the test function for various testing.
    '''

def test():

    #Set up the test file.
    pwd = os.path.dirname(__file__)
    test_exe_fullpath = os.path.join(pwd,'../testexe/test2_keyboy_wab32res.dll')
    
    #Instantiate the class
    utils = r2utils()

    #Test get_funcj_list_from_file
    funcj_list = utils.get_funcj_list_from_file(test_exe_fullpath)

    print '\nTest check_is_import_func\n'

    for funcj in funcj_list:
        if utils.check_is_import_func(funcj):
           #print json.dumps(funcj, indent=4)
           print funcj['name']

    print '\nTest check_is_thunk_func\n'

    for funcj in funcj_list:
        if utils.check_is_thunk_func(funcj):
           #print json.dumps(funcj, indent=4)
           print funcj['name']

    print '\nTest check_is_wrapper_func\n'

    for funcj in funcj_list:
        if utils.check_is_wrapper_func(funcj):
           #print json.dumps(funcj, indent=4)
           print funcj['name']

    print '\nTest check_is_first_round_func\n'

    for funcj in funcj_list:
        if utils.check_is_first_round_func(funcj):
           #print json.dumps(funcj, indent=4)
           print funcj['name']

    print '\nTest check_is_utility_func\n'

    for funcj in funcj_list:
        if utils.check_is_utility_func(funcj):
           #print json.dumps(funcj, indent=4)
           print funcj['name']        



if __name__ == "__main__":
    test()