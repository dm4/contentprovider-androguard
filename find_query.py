#!/usr/bin/env python

from androguard.core.bytecodes import dvm, apk
from androguard.core.analysis import analysis
from androguard.decompiler.dad import decompile
import androlyze
from androlyze import *
import os, re

apk_session_dir = "session/"
ERROR_MSG_PREFIX = "\033[1;31m[!]\033[m "
OK_MSG_PREFIX = "\033[1;32m[+]\033[m "
WARN_MSG_PREFIX = "\033[0;33m[*]\033[m "

def read_apk(apk_name):
    """ Read apk file and return a, d, dx """
    apk_basename = os.path.basename(apk_name)
    apk_session_name = apk_session_dir + apk_basename

    # mkdir session
    if not os.path.isdir(apk_session_dir):
        os.system("mkdir '{}'".format(apk_session_dir))

    # check if session saved
    if not os.path.isfile(apk_session_name):
        a, d, dx = AnalyzeAPK(apk_name)
        androlyze.save_session([a, d, dx], apk_session_name)
    else:
        a, d, dx = androlyze.load_session(apk_session_name)

    return a, d, dx

def get_method_variable(method):
    """ Return local variable list and parameter list """
    # get number of local variables
    nb  = method.get_code().get_registers_size()

    # parameters pass in
    ret = method.proto.split(')')
    params = ret[0][1:].split()

    # NOT SAVE CLASS OF PARAMS YET
    if params:
        return [ "v{:d}".format(i) for i in range(0, nb - len(params)) ], [ "v{:d}".format(i) for i in range(nb - len(params), nb) ]
    else :
        return [ "v{:d}".format(i) for i in range(0, nb) ], []

def get_instruction_variable(instruction):
    # opcode is invoke-xxx/range
    if instruction.get_name()[-6:] == '/range':
        var_from, var_to = instruction.get_output().split(', ')[0].split(' ... ')
        var_from = int(var_from[1:])
        var_to   = int(var_to[1:])
        return [ "v{:d}".format(i) for i in range(var_from, var_to + 1) ]
    else:
        return [ var for var in instruction.get_output().split(', ') if var[0] == 'v' ]

def get_invoke_info(ins_output):
    """ Will return class_name, method_name """
    method_code = ins_output.split(', ')[-1]
    m = re.match('^L([^;]*);(?:->(.*)\()?', method_code)
    class_name, method_name = m.group(1), m.group(2)
    return class_name, method_name

def get_get_object_info(ins_output):
    method_code = ins_output.split(', ')[-1]
    m = re.match('^L([^;]*);->([^ ]*)', method_code)
    class_name, attribute_name = m.group(1), m.group(2)
    return class_name, attribute_name

def _print_backtrace_result(result, depth):
    indent = "    " * depth
    ins = result["ins"]
    if type(ins) == type('str'):
        print OK_MSG_PREFIX + indent + ins
    else:
        print OK_MSG_PREFIX + indent + "{:16s}{}".format(ins.get_name(), ins.get_output())
    for var in result.keys():
        if var == 'ins':
            continue
        print OK_MSG_PREFIX + indent + var
        _print_backtrace_result(result[var], depth + 1)

def _print_backtrace_result_decompile(result):
    ins = result["ins"]
    if type(ins) == type('str'):
        return ins
    else:
        param_list = get_instruction_variable(ins)
        if ins.get_name() == "invoke-static":
            class_name, method_name = get_invoke_info(ins.get_output())
            r = "{}.{}(".format(class_name, method_name)
            for param in param_list:
                r += _print_backtrace_result_decompile(result[param])
            r += ")"
            return r
        elif ins.get_name() == "invoke-virtual" or ins.get_name() == "invoke-direct":
            class_name, method_name = get_invoke_info(ins.get_output())
            instance = param_list.pop(0)
            r = "{}.{}(".format(_print_backtrace_result_decompile(result[instance]), method_name)
            add_comma = False
            for param in param_list:
                if add_comma:
                    r += ", "
                else:
                    add_comma = True
                r += _print_backtrace_result_decompile(result[param])
            r += ")"
            return r
        elif ins.get_name() == "const-string" or ins.get_name() == "const/4":
            return ins.get_output().split(', ')[-1]
        elif ins.get_name() == "new-instance":
            class_name, method_name = get_invoke_info(ins.get_output())
            return "new {}".format(class_name)
        elif ins.get_name() == "iget-object":
            class_name, attribute_name = get_get_object_info(ins.get_output())
            r = "{}.{}".format(_print_backtrace_result_decompile(result[param_list[1]]), attribute_name)
            return r
        elif ins.get_name() == "sget-object":
            class_name, attribute_name = get_get_object_info(ins.get_output())
            r = "{}.{}".format(class_name, attribute_name)
            return r
        return "{} {}".format(ins.get_name(), ins.get_output())

def print_backtrace_result(result, decompile=1):
    if decompile == 1:
        print _print_backtrace_result_decompile(result)
    else:
        _print_backtrace_result(result, 0);

def backtrace_variable(method, ins_addr, var):
    # the last local variable of a method is 'this'
    mvar_list_local, mvar_list_param = get_method_variable(method.get_method())
    if var == mvar_list_local[-1]:
        return {"ins": 'this'}

    # skip the param
    if var in mvar_list_param:
        print WARN_MSG_PREFIX + "\033[1;30mFound {} in param list\033[0m".format(var)
        return {"ins": 'SKIP PARAM'}

    # prepare regular expression
    re_var = re.compile(var)

    # get mappings
    #     index -> instruction mapping
    #     block -> address list mapping
    idx = 0
    instruction_dict = {}
    block_address_list = {}
    blocks = [ block for block in method.get_basic_blocks().get() ]
    for block in blocks:
        address_list = []
        for ins in block.get_instructions():
            instruction_dict[idx] = ins
            address_list.append(idx)
            idx += ins.get_length()
        block_address_list[block] = address_list

    # find block contains target instruction
    ins_index_in_block = None
    target_block = None
    for block in reversed(blocks):
        if block.get_start() > ins_addr:
            continue
        idx = block.get_start()
        instructions = block.get_instructions()
        for i in range(0, len(instructions)):
            ins = instructions[i]
            if idx == ins_addr:
                ins_index_in_block = i
                target_block = block
                break
            previous_idx = idx
            idx += ins.get_length()
        if target_block is not None:
            break

    #
    current_block = target_block
    address_list  = block_address_list[current_block]
    address_list  = [ addr for addr in address_list if addr < ins_addr ]
    depth = {}
    depth[current_block] = 0
    result = None
    stack  = []
    while result is None:
        instructions  = current_block.get_instructions()
        current_depth = depth[current_block]
        for i in range(ins_index_in_block - 1, -1, -1):
            idx = address_list.pop()
            ins = instructions[i]
            # print
            print WARN_MSG_PREFIX + "\033[1;34m{:04x}\033[0m {:20s} {}".format(idx, ins.get_name(), ins.get_output())
            if re_var.match(ins.get_output()):
                if ins.get_name() == "sget-object" or ins.get_name() == "new-instance" or ins.get_name() == "const-string" or ins.get_name() == "const/4":
                    print WARN_MSG_PREFIX + "\033[1;30mFound {}\033[0m".format(var)
                    result = {"ins": ins}
                    return result
                elif ins.get_name() == "iget-object":
                    ivar_list = get_instruction_variable(ins)
                    if ivar_list[0] == var:
                        result = {"ins": ins}
                        for i in range(1, len(ivar_list)):
                            ivar = ivar_list[i]
                            print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {}\033[0m".format(ivar)
                            result[ivar] = backtrace_variable(method, idx, ivar)
                        return result
                elif ins.get_name() == "move-result-object":
                    # get previous instruction
                    i -= 1
                    ins = instructions[i]
                    idx = address_list.pop()
                    #
                    print WARN_MSG_PREFIX + "\033[1;30mFound {}\033[0m".format(var)
                    ivar_list = get_instruction_variable(ins)
                    result = {"ins": ins}
                    print WARN_MSG_PREFIX + "\033[1;30m{:04x} {:20s} {}\033[0m".format(idx, ins.get_name(), ins.get_output())
                    for ivar in ivar_list:
                        print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {}\033[0m".format(ivar)
                        result[ivar] = backtrace_variable(method, idx, ivar)
                    return result
                elif ins.get_name() == "invoke-direct" or ins.get_name() == "invoke-virtual":
                    ivar_list = get_instruction_variable(ins)
                    result = {"ins": ins}
                    print WARN_MSG_PREFIX + "\033[1;30m{:04x} {:20s} {}\033[0m".format(idx, ins.get_name(), ins.get_output())
                    for ivar in ivar_list:
                        print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {}\033[0m".format(ivar)
                        result[ivar] = backtrace_variable(method, idx, ivar)
                    return result
                elif ins.get_name() == "check-cast":
                    continue
                else:
                    print "\t\tWhat? Instruction No Define!"
        if result == None:
            if len(stack) > 0:
                print WARN_MSG_PREFIX + "\033[1;30mPop From Stack\033[0m"
                current_block = stack.pop(0)
                address_list  = block_address_list[current_block]
            else:
                previous_blocks = current_block.get_prev()
                if len(previous_blocks) > 0:
                    # push blocks to stack
                    print WARN_MSG_PREFIX + "\033[1;30mFind {:d} Prev Block(s)\033[0m".format(len(previous_blocks))
                    for block in current_block.get_prev():
                        stack.append(block[2])
                        depth[block[2]] = current_depth + 1
                    # pop block to process
                    current_block = stack.pop(0)
                    address_list  = block_address_list[current_block]
                    ins_index_in_block = current_block.get_nb_instructions()
                else:
                    print WARN_MSG_PREFIX + "\033[1;30mNo Prev Block\033[0m"
                    return None

    print "\tFound {}".format(result)
    print ""

def get_instruction_by_idx(method, idx):
    # find query instruction position
    idx = 0
    blocks = method.get_basic_blocks().get()
    for block in blocks:
        instructions = block.get_instructions()
        for index in range(0, len(instructions)):
            ins = instructions[index]
            if idx == path.get_idx():
                return ins
            idx += ins.get_length()

if __name__ == "__main__" :
    # load apk and analyze
    a, d, dx = read_apk("apk/tunein.player.apk")

    # search ContentResolver.query()
    query_paths = dx.tainted_packages.search_methods("^Landroid/content/ContentResolver;$", "^query$", ".")
    print "Found %d path(s)." % len(query_paths)

    # prepare regular expression
    re_skip_class = re.compile('Landroid|Lcom/google')

    for i in range(0, len(query_paths)):
        path = query_paths[i]
        print "Path {:2d}".format(i)

        # get source class & method name
        cm = d.get_class_manager()
        src_class_name, src_method_name, src_descriptor = path.get_src(cm)
        print "\tClass  {0}".format(src_class_name)
        print "\tMethod {0}".format(src_method_name)
        print "\tOffset 0x{0:04x}".format(path.get_idx())

        # get analyzed method
        method = d.get_method_descriptor(src_class_name, src_method_name, src_descriptor)
        analyzed_method = dx.get_method(method)

        # skip built-in library
        if re_skip_class.match(src_class_name):
            print "Skip {}".format(src_class_name)
            continue

        # get variable name
        target_ins = get_instruction_by_idx(analyzed_method, path.get_idx())
        uri_variable = get_instruction_variable(target_ins)[1]

        # backtrace variable
        result = backtrace_variable(analyzed_method, path.get_idx(), uri_variable)
        print_backtrace_result(result)
