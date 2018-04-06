import re
import sys
import random


global seed 

seed = random.randint(0,500)

variables = {}
def replace_variables (code):

    code = remove_comments(code)
    
    # variables contains the names of all the 
    # variables that have been assigned values in the code
    
    for var in re.finditer(r"([\$\w]+)\s*(=|\()", code):
        global variables 
        variables[var.group(1)] = random_name_generator()
    newCode = " " + code
    for var in variables:
        newCode = re.sub( r'(\s+)'+r'('+re.escape(var)+r')'+r'(\s*|\.|\()', r'\1'+variables[var]+r'\3', newCode)
    return newCode  
    

def random_name_generator ():
    global seed
    seed = seed + 1
    return '_'+hex(seed)


def remove_spaces(code):
    x = re.sub(r'([\$\w])(\s+)([^\$\w])', r'\1\3', code)
    y = re.sub(r'([^\w\$])(\s+)([^\w\$])', r'\1\3', x)
    return re.sub(r'([^\$\w])(\s+)([\$\w])', r'\1\3', y)


def remove_strings(code):
    newcode = code
    stringArray = {}
    global seed 
    seed = seed + 1
    for string in re.finditer(r"\"[^\"]+\"", code): 
        # add string to array
        stringArray[string.group(0)] = True
    for string in re.finditer(r"\'[^\']+\'", code): 
        # add string to array
        stringArray[string.group(0)] = True
    jsarray = "var _"+ hex(seed)+"=["
    for idx,item in enumerate(stringArray):
        jsarray = jsarray +"\"" +convert_string_to_hex(item) + "\""+ ","
        newcode = re.sub(re.escape(item),hex(seed)+"["+str(idx)+ "]", newcode)
        newcode = re.sub(re.escape(item),hex(seed)+"["+str(idx)+ "]", newcode)
    
    jsarray = jsarray[:-1]+"];"
    return (jsarray, newcode)
def convert_string_to_hex(string):
    return re.sub(r'(.{2})', r'\x\1', string.encode("utf-8").hex())

def store_strings(strings, code):
    return strings + code   

def remove_comments(string):
    return re.sub(r'(\/\*(.|\n)*\*\/)|(\/\/.*\n)','',string)


def jsObfuscate(code):

    result = remove_strings(code)
    stringarray = result[0]
    code = result[1]
    code = stringarray+remove_spaces(replace_variables(code))

    return code
