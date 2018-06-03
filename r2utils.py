'''
Author: Matt Brooks, @cmatthewbrooks

DESCRIPTION:

This module includes multiple utility classes to assist
in working with radare2 over r2pipe.

R2PipeUtility - designed to work directly on a pipe object.
R2FuncUtility - designed to work on funcj objects from 'pdfj'.
R2CallUtility - designed to work on CALL type opcodesself.
R2ParseUtility - designed to parse random strings from disassembly objects.

'''

import os
import json

import r2pipe

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
            return []

        funcj_list = []

        functions = r2.cmdj("aflj")

        if functions:

            for func in functions:

                funcj = r2.cmdj("pdfj @ " + hex(func['offset']))

                if funcj:

                    funcj_list.append(funcj)

        return funcj_list

    @staticmethod
    def get_aflj_list(r2):

        if not str(r2.__class__) == R2PipeUtility.R2PIPE_CLASS_NAME:
            return {}

        functions = r2.cmdj("aflj")

        if functions:
            return functions
        else:
            return {}

class R2FuncUtility:
    '''
    Methods in this class are designed to operate on funcj objects
    returned from the r2 command 'pdfj'.
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

        return R2ParseUtility.parse_import_from_import_jmp_opcode(op)

    # The get_call_from_wrapper method needs better thought and
    # design. It's hacky right now.

    @staticmethod
    def get_call_from_wrapper(funcj):

        wrapper_call = ''

        for op in funcj['ops']:
            if 'call' in op.get('opcode','N/A'):
                wrapper_call = op.get('opcode','N/A')

        return wrapper_call

class R2FlagUtility:
    '''
    Methods in this class are helpers to work with flag spaces.
    '''

    THUNK_FS = 'thunk-funcs'
    WRAPPER_FS = 'wrapper-funcs'
    GLOBAL_ASSIGNMENT_FS = 'global-assignments'
    LIBRARY_CODE_FS = 'library-funcs'

    @staticmethod
    def check_if_flagspace_exists(flagspace, fsj):

        for fs in fsj:

            if fs['name'] == flagspace:

                return True

        return False

class R2CallUtility:
    '''
    Methods in this class are designed to operate on 'CALL' opcodes.
    '''
    def __init__(self):
        pass


class R2ParseUtility:
    '''
    Methods in this class handle various string parsing for strings
    found in disassembly.

    All methods in this class should have @staticmethod decorators
    so they can easily be used by other class methods in this module.
    '''

    # Note: the prefix1/2 logic was added after an r2
    # update. There is an inconsistency in the bracket between
    # the visible disassembly and what the json returns via
    # a pipe.

    WINAPI_IMP_PREFIX_1 = 'jmp dword ['
    WINAPI_IMP_PREFIX_2 = 'jmp dword '

    @staticmethod
    def parse_import_from_import_jmp_opcode(opcode):

        import_string = opcode.get('disasm','N/A')

        if R2ParseUtility.WINAPI_IMP_PREFIX_1 in opcode.get('disasm','N/A'):
            return import_string[
                len(R2ParseUtility.WINAPI_IMP_PREFIX_1):len(import_string)-1
                ]

        elif R2ParseUtility.WINAPI_IMP_PREFIX_2 in opcode.get('disasm','N/A'):
            return import_string[
                len(R2ParseUtility.WINAPI_IMP_PREFIX_2):len(import_string)
                ]

        else:
            return ''
