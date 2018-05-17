
import os,sys
import argparse
import json, base64

import r2pipe

import r2utils as r2u

r2utils = r2u.R2Utils()


def print_func_strings(r2):

    string_sets = {}

    # First, get the strings and for each string, make sure it is
    # ascii or wide.
    strings = r2.cmdj("izzj")

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
    else:
        raise Exception("Error: izzj returned no strings.")

    print json.dumps(string_sets, indent=4)

if __name__ == '__main__':

    r2 = r2utils.get_analyzed_r2pipe_from_input()

    print_func_strings(r2)

    r2.quit()