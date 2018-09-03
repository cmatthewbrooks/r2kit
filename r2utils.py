'''
Author: Matt Brooks, @cmatthewbrooks

DESCRIPTION:

This module includes multiple utility classes to assist
in working with radare2 over r2pipe.

'''

import os
import json

import r2pipe

REGISTERS = ['eax','ebx','ecx','edx','esi','edi','esp','ebp']

class R2PipeUtility:
    '''
    Methods in this class are designed to work directly on a r2pipe
    object.
    '''

    R2PIPE_CLASS_NAME = 'r2pipe.open'

    @staticmethod
    def get_analyzed_r2pipe_from_input(input_obj = None):

        if not input_obj:
            r2 = r2pipe.open()
        elif str(input_obj.__class__) == R2PipeUtility.R2PIPE_CLASS_NAME:
            r2 = input_obj
        elif os.path.isfile(input_obj):
            r2 = r2pipe.open(input_obj)
        else:
            raise Exception('Error: Not inside an r2 session.')

        try:
            r2.cmd("aflc")
        except IOError:
            raise Exception('Error: Not inside an r2 session.')


        if int(r2.cmd('aflc')) == 0:
            # If there are no functions, analyze the file
            r2.cmd("aa; aar; aac")


        return r2

    @staticmethod
    def get_funcj_list(r2):

        if not str(r2.__class__) == R2PipeUtility.R2PIPE_CLASS_NAME:
            raise Exception('Error: Not inside an r2 session.')

        funcj_list = []

        functions = r2.cmdj("aflj")

        if functions:

            for func in functions:

                funcj = r2.cmdj("pdfj @ " + hex(func['offset']))

                if funcj:

                    funcj_list.append(funcj)

        return funcj_list

    @staticmethod
    def get_function_start_from_offset(r2, offset=None):

        if not str(r2.__class__) == R2PipeUtility.R2PIPE_CLASS_NAME:
            raise Exception('Error: Not inside an r2 session.')

        if offset:
            return r2.cmdj('afij @ ' + hex(offset))[0]['offset']
        else:
            return r2.cmdj('afij')[0]['offset']

    @staticmethod
    def get_args_count_to_function_offset(r2, offset=None):

        if not str(r2.__class__) == R2PipeUtility.R2PIPE_CLASS_NAME:
            raise Exception('Error: Not inside an r2 session.')

        if offset:
            return r2.cmdj('afij @ ' + hex(offset))[0]['nargs']
        else:
            return r2.cmdj('afij')[0]['nargs']


    @staticmethod
    def get_call_xref_list_to_function_offset(r2, offset=None):

        if not str(r2.__class__) == R2PipeUtility.R2PIPE_CLASS_NAME:
            raise Exception('Error: Not inside an r2 session.')

        xref_list = []

        if offset:
            funcj = r2.cmdj('pdfj @ ' + hex(offset))
        else:
            funcj = r2.cmdj('pdfj')

        # The [0] hack is because xrefs to the function will
        # only be included in the first ops entry.
        if 'xrefs' in funcj['ops'][0]:
            for xref in funcj['ops'][0]['xrefs']:
                if xref['type'] == 'CALL':
                    xref_list.append(xref['addr'])

        return xref_list

class R2FuncUtility:
    '''
    Methods in this class are designed to operate on funcj objects
    returned from the r2 command 'pdfj' or afij objects returned
    from the afij command.
    '''

    IMPORT = 'import'
    GLOBAL = 'global'
    THUNK = 'thunk'
    WRAPPER = 'wrapper'
    FIRST_ROUND = 'firstround'
    UTILITY = 'utility'
    UNKNOWN = 'unknown'

    @staticmethod
    def classify_func(self, funcj):

        if R2FuncUtility.check_is_import_jmp_func(funcj):
            return R2FuncUtility.IMPORT
        elif R2FuncUtility.check_is_global_assignment_func(funcj):
            return R2FuncUtility.GLOBAL
        elif R2FuncUtility.check_is_thunk_func(funcj):
            return R2FuncUtility.THUNK
        elif R2FuncUtility.check_is_wrapper_func(funcj):
            return R2FuncUtility.WRAPPER
        elif R2FuncUtility.check_is_first_round_func(funcj):
            return R2FuncUtility.FIRST_ROUND
        elif R2FuncUtility.check_is_utility_func(funcj):
            return R2FuncUtility.UTILITY
        else:
            return R2FuncUtility.UNKNOWN

    @staticmethod
    def check_is_analysis_func(funcj):

        if (R2FuncUtility.check_is_import_jmp_func(funcj) or
            R2FuncUtility.check_is_global_assignment_func(funcj) or
            R2FuncUtility.check_is_thunk_func(funcj) or
            R2FuncUtility.check_is_wrapper_func(funcj)):

            return False

        else:

            return True

    @staticmethod
    def check_is_import_jmp_func(funcj):

        if (len(funcj['ops']) == 1
            and funcj['size'] == 6
            and funcj['ops'][0]['type'] == 'jmp'):

            return True

        else:

            return False

    @staticmethod
    def check_is_global_assignment_func(funcj):

        if (funcj['ops'][0]['type'] == 'mov'
            and funcj['ops'][1]['type'] == 'ret'):

            return True

        else:

            return False

    @staticmethod
    def check_is_thunk_func(funcj):

        if 1 < len(funcj['ops']) <= 3:

            return True

        else:

            return False

    @staticmethod
    def check_is_wrapper_func(funcj):

        calls = R2FuncUtility.get_call_count_from_funcj(funcj)

        if (len(funcj['ops']) > 3 and
            len(funcj['ops']) <= 20 and
            calls == 1):

            return True

        else:

            return False

    @staticmethod
    def check_is_first_round_func(funcj):

        calls = R2FuncUtility.get_call_count_from_funcj(funcj)

        if calls == 0:

            return True

        elif calls > 0:

            return False

    @staticmethod
    def check_is_utility_func(funcj):

        call_xref_count = 0

        if 'xrefs' in funcj['ops'][0]:
            for xref in funcj['ops'][0]['xrefs']:
                if xref['type'] == 'CALL':
                    call_xref_count += 1

        if call_xref_count >= 3:
            return True
        elif call_xref_count <= 2:
            return False

    @staticmethod
    def get_call_count_from_funcj(funcj):

        count = 0

        for op in funcj['ops']:

            if 'call' in op.get('opcode','N/A'):
                count += 1

        return count

    @staticmethod
    def get_import_from_import_jmp_func(funcj):

        op = funcj['ops'][0]

        return R2ParserUtility.parse_import_from_import_jmp_disasm(op)

    # The get_call_from_wrapper method needs better thought and
    # design. It's hacky right now.

    @staticmethod
    def get_call_from_wrapper(funcj):

        wrapper_call = ''

        for op in funcj['ops']:
            if 'call' in op.get('disasm','N/A'):
                wrapper_call = op.get('disasm','N/A')

        return wrapper_call

    @staticmethod
    def get_raw_call_chain_from_funcj(funcj):

        call_chain = []

        for op in funcj['ops']:
            if op['type'] in ['call','ucall']:
                call_chain.append(op['disasm'])

        return call_chain

    @staticmethod
    def get_func_stats_list_from_afij(afij):
        pass


    @staticmethod
    def check_is_complex_func(afij):

        if afij['nbbs'] > 5:
            return True
        else:
            return False

class R2InstructionUtility:
    '''
    Methods in this class operate on instructions typically returned
    by 'pdj 1' or pdfj['ops'].
    '''

    @staticmethod
    def is_mutator_instruction(pdj):

        if pdj['type'] in ['mov','lea','add','sub']:
            return True
        else:
            return False

    @staticmethod
    def get_disasm_mutator(disasm):

        return disasm.split(',')[1]

class R2CallUtility:

    CALL_TYPE_DIRECT = 'direct'
    CALL_TYPE_INDIRECT = 'indirect'
    CALL_TYPE_IMPORT = 'import'
    CALL_TYPE_LIBRARY = 'library'
    CALL_TYPE_REGISTER = 'register'
    CALL_TYPE_UNDEFINED = 'undefined'

    CALL_PREFIX_DIRECT = 'fcn.'
    CALL_PREFIX_INDIRECT = ['loc.','call dword [0x']
    CALL_PREFIX_IMPORT = 'sym.imp.'
    CALL_PREFIX_LIBRARY = 'sym.'


    @staticmethod
    def classify_call_disasm(disasm):

        if check_is_call_type_direct(disasm):
            return R2CallUtility.CALL_TYPE_DIRECT
        elif check_is_call_type_indirect(disasm):
            return R2CallUtility.CALL_TYPE_INDIRECT
        elif check_is_call_type_import(disasm):
            return R2CallUtility.CALL_TYPE_IMPORT

    @staticmethod
    def check_is_call_type_direct(disasm):

        if R2CallUtility.CALL_PREFIX_DIRECT in disasm:
            return True
        else:
            return False

    @staticmethod
    def check_is_call_type_indirect(disasm):

        if any([prefix in disasm for prefix in R2CallUtility.CALL_PREFIX_INDIRECT]):
            return True
        else:
            return False

    @staticmethod
    def check_is_call_type_import(disasm):

        if R2CallUtility.CALL_PREFIX_IMPORT in disasm:
            return True
        else:
            return False


class R2ParserUtility:
    '''
    Methods in this class handle various string parsing for strings
    found in disassembly.
    '''

    # Note: the prefix1/2 logic was added after an r2
    # update. There is an inconsistency in the bracket between
    # the visible disassembly and what the json returns via
    # a pipe.

    WINAPI_IMP_PREFIX_1 = 'jmp dword ['
    WINAPI_IMP_PREFIX_2 = 'jmp dword '

    @staticmethod
    def parse_import_from_import_jmp_disasm(opcode):

        import_string = opcode.get('disasm','N/A')

        if R2ParserUtility.WINAPI_IMP_PREFIX_1 in opcode.get('disasm','N/A'):
            return import_string[
                len(R2ParserUtility.WINAPI_IMP_PREFIX_1):len(import_string)-1
                ]

        elif R2ParserUtility.WINAPI_IMP_PREFIX_2 in opcode.get('disasm','N/A'):
            return import_string[
                len(R2ParserUtility.WINAPI_IMP_PREFIX_2):len(import_string)
                ]

        else:
            return ''

class R2FlagUtility:
    '''
    Methods in this class are helpers to work with flag spaces.
    '''

    R2KIT_ANALYZED_FS = 'r2kit-analyzed-funcs'
    DEVELOPER_FS = 'developer-funcs'
    THUNK_FS = 'thunk-funcs'
    WRAPPER_FS = 'wrapper-funcs'
    GLOBAL_ASSIGNMENT_FS = 'global-assignment-funcs'
    LIBRARY_CODE_FS = 'library-funcs'

    R2KIT_ANALYZED_FLAG = 'r2kit-analyzed-func'
    DEVELOPER_FLAG = 'developer-func'
    THUNK_FLAG = 'thunk-func'
    WRAPPER_FLAG = 'wrapper-func'
    GLOBAL_ASSIGNMENT_FLAG = 'global-assignment-func'
    LIBRARY_CODE_FLAG = 'library-func'

    R2KIT_ANALYZED_FLAG_HACK = 'r2kit_analyzed_func'
    DEVELOPER_FLAG_HACK = 'developer_func'
    THUNK_FLAG_HACK = 'thunk_func'
    WRAPPER_FLAG_HACK = 'wrapper_func'
    GLOBAL_ASSIGNMENT_FLAG_HACK = 'global_assignment_func'
    LIBRARY_CODE_FLAG_HACK = 'library_func'

    @staticmethod
    def check_if_flagspace_exists(flagspace, fsj):

        for fs in fsj:

            if fs['name'] == flagspace:

                return True

        return False

    @staticmethod
    def get_developer_func_offsets_from_flagspace(fj):

        developer_funcs = []

        for f in fj:

            if f['name'] == R2FlagUtility.DEVELOPER_FLAG_HACK:

                developer_funcs.append(f['offset'])

        return developer_funcs
