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

def write_log_to_file(filename, string):
    f = open(filename, 'a')
    f.write(string)
    f.close()

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
        var_str= instruction.get_output().split(', ')[0]
        if var_str.find(" ... ") != -1:
            var_from, var_to = instruction.get_output().split(', ')[0].split(' ... ')
            var_from = int(var_from[1:])
            var_to   = int(var_to[1:])
            return [ "v{:d}".format(i) for i in range(var_from, var_to + 1) ]
        else:
            return [ var_str ]
    else:
        return [ var for var in instruction.get_output().split(', ') if var[0] == 'v' ]

def get_invoke_info(ins_output):
    """ Will return class_name, method_name """
    method_code = ins_output.split(', ')[-1]
    m = re.match('^L([^;]*);->(.*)\((.*)\)', method_code)
    class_name, method_name, param_string = m.group(1), m.group(2), m.group(3)
    return class_name, method_name, [] if param_string == "" else param_string.split(' ')

def get_get_object_info(ins_output):
    """ use for iget-object & sget-object """
    method_code = ins_output.split(', ')[-1]
    m = re.match('^L([^;]*);->([^ ]*)', method_code)
    class_name, attribute_name = m.group(1), m.group(2)
    return class_name, attribute_name

def get_analyzed_method_from_path(path):
    src_class_name, src_method_name, src_descriptor = path.get_src(cm)
    method = d.get_method_descriptor(src_class_name, src_method_name, src_descriptor)
    analyzed_method = dx.get_method(method)
    return analyzed_method

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
            class_name, method_name, method_param_list = get_invoke_info(ins.get_output())
            r = "{}.{}(".format(class_name, method_name)
            j = 0
            for i in range(0, len(method_param_list)):
                param = param_list[j]
                r += _print_backtrace_result_decompile(result[param])
                if method_param_list[i] in ('J', 'D'):
                    j += 2
                else:
                    j += 1
            r += ")"
            return r
        elif ins.get_name() == "invoke-virtual" or ins.get_name() == "invoke-direct":
            class_name, method_name, method_param_list = get_invoke_info(ins.get_output())
            instance = param_list.pop(0)
            r = "{}.{}(".format(_print_backtrace_result_decompile(result[instance]), method_name)
            add_comma = False
            j = 0
            for i in range(0, len(method_param_list)):
                param = param_list[j]
                if add_comma:
                    r += ", "
                else:
                    add_comma = True
                r += _print_backtrace_result_decompile(result[param])
                if method_param_list[i] in ('J', 'D'):
                    j += 2
                else:
                    j += 1
            r += ")"
            return r
        elif ins.get_name() == "const-string" or ins.get_name() == "const/4":
            return ins.get_output().split(', ')[-1]
        elif ins.get_name() == "new-instance":
            # trim the Lclass_name;
            class_name = ins.get_output().split(', ')[-1][1:-1]
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
        print OK_MSG_PREFIX + "Result: {}".format(_print_backtrace_result_decompile(result))
    else:
        _print_backtrace_result(result, 0);

def backtrace_variable(method, ins_addr, var):
    # get local vars & param vars passed in
    mvar_list_local, mvar_list_param = get_method_variable(method.get_method())

    # the last local variable of a non-static method is 'this'
    #     0x08 is static flag
    if not 'static' in method.get_method().get_access_flags_string().split(' '):
        if var == mvar_list_local[-1]:
            return {"ins": 'this'}

    # if is param, get caller method & backtrace
    result = None
    caller_stack = []
    if var in mvar_list_param:
        # escape for regular expression
        descriptor = method.get_method().get_descriptor().replace('(', '\(').replace(')', '\)').replace('[', '\[').replace(']', '\]')
        print WARN_MSG_PREFIX + "\033[1;30mFound {} in param list\033[0m".format(var)

        # find caller path
        caller_paths = dx.tainted_packages.search_methods(method.get_method().get_class_name(), method.get_method().get_name(), descriptor)

        # find no caller
        if len(caller_paths) == 0:
            print WARN_MSG_PREFIX + "\033[1;30mNO ONE CALL YOU\033[0m"
            return {"ins": "null"}

        # find the paths
        for path in caller_paths:
            # get analyzed method
            analyzed_method = get_analyzed_method_from_path(path)
            print WARN_MSG_PREFIX + analyzed_method.get_method().get_class_name(), analyzed_method.get_method().get_name(), analyzed_method.get_method().get_descriptor()

            # get variable name
            target_ins = get_instruction_by_idx(analyzed_method, path.get_idx())
            print WARN_MSG_PREFIX + target_ins.get_name(), target_ins.get_output()
            print WARN_MSG_PREFIX, get_instruction_variable(target_ins)

            # decide the target var index in the instruction
            target_var_list = get_instruction_variable(target_ins)
            target_param_index = mvar_list_param.index(var)
            # invoke-direct / invoke-virtual will pass one more param as instance
            if target_ins.get_name() in ( 'invoke-direct', 'invoke-virtual', 'invoke-direct/range'):
                target_var = target_var_list[target_param_index + 1]
            elif target_ins.get_name() in ('invoke-static', 'invoke-static/range'):
                target_var = target_var_list[target_param_index]
            else:
                print WARN_MSG_PREFIX + '\033[1;30mNOT IMPLEMENT YET: {}\033[0m'.format(target_ins.get_name())
            print WARN_MSG_PREFIX + "\033[1;30mFind {}\033[0m".format(target_var)

            # recursive find the result
            result = backtrace_variable(analyzed_method, path.get_idx(), target_var)
            if result is not None:
                return result

    # prepare regular expression
    re_var = re.compile(var + '([^0-9a-zA-Z_]|$)')

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

    # main algorithm
    current_block = target_block
    address_list  = list(block_address_list[current_block])
    address_list  = [ addr for addr in address_list if addr < ins_addr ]
    stack  = []
    traced_block = {}
    traced_block[current_block] = True
    while True:
        instructions  = current_block.get_instructions()

        # start backtracing
        for i in range(ins_index_in_block - 1, -1, -1):
            idx = address_list.pop()
            ins = instructions[i]
            print WARN_MSG_PREFIX + "\033[1;34m{:04x}\033[0m {:20s} {}".format(idx, ins.get_name(), ins.get_output())

            # match the instruction to search the target var
            if re_var.match(ins.get_output()):
                if ins.get_name() in ("sget-object", "const-class", "new-instance", "const-string", "const", "const/4", "const/16"):
                    print WARN_MSG_PREFIX + "\033[1;30mFound {}\033[0m".format(var)
                    result = {"ins": ins}
                    return result
                elif ins.get_name() in ("iget-object", "aget-object", "move", "move-object", "move-object/from16", "new-array"):
                    print WARN_MSG_PREFIX + "\033[1;30mFound {}\033[0m".format(var)
                    ivar_list = get_instruction_variable(ins)

                    # check target var is the first var in the instruction
                    if ivar_list[0] == var:
                        result = {"ins": ins}

                        # backtrace other var in the instruction
                        for i in range(1, len(ivar_list)):
                            ivar = ivar_list[i]
                            print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {}\033[0m".format(ivar)
                            result[ivar] = backtrace_variable(method, idx, ivar)
                        return result
                    else:
                        print ERROR_MSG_PREFIX + "ERROR ", ins.get_name(), ins.get_output()
                elif ins.get_name() in ("move-result-object", "move-result-wide", "move-result"):
                    print WARN_MSG_PREFIX + "\033[1;30mFound {}\033[0m".format(var)

                    # get previous instruction
                    i -= 1
                    ins = instructions[i]
                    idx = address_list.pop()

                    # backtrace all other vars in the instruction
                    #     - aware: long(J)/double(D) will have two register
                    ivar_list = get_instruction_variable(ins)
                    result = {"ins": ins}
                    print WARN_MSG_PREFIX + "\033[1;30m{:04x} {:20s} {}\033[0m".format(idx, ins.get_name(), ins.get_output())

                    param_list = get_invoke_info(ins.get_output())[2]
                    if ins.get_name() in ("invoke-static"):
                        ivar_index = 0
                    else:
                        ivar_index = 1
                        ivar = ivar_list[0]
                        print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {}\033[0m".format(ivar)
                        result[ivar] = backtrace_variable(method, idx, ivar)

                    param_index = 0
                    while ivar_index < len(ivar_list):
                        ivar = ivar_list[ivar_index]
                        print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {}\033[0m".format(ivar)
                        result[ivar] = backtrace_variable(method, idx, ivar)
                        if param_list[param_index] in ('J', 'D'):
                            ivar_index += 2
                        else:
                            ivar_index += 1
                        param_index += 1

                    return result
                elif ins.get_name() in ("invoke-direct", "invoke-virtual", "invoke-static", "invoke-direct/range"):
                    ivar_list = get_instruction_variable(ins)
                    result = {"ins": ins}

                    # backtrace all other vars in the instruction
                    #     - aware: long(J)/double(D) will have two register
                    param_list = get_invoke_info(ins.get_output())[2]
                    if ins.get_name() in ("invoke-static"):
                        ivar_index = 0
                    else:
                        ivar_index = 1
                        ivar = ivar_list[0]
                        print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {}\033[0m".format(ivar)
                        result[ivar] = backtrace_variable(method, idx, ivar)

                    param_index = 0
                    while ivar_index < len(ivar_list):
                        ivar = ivar_list[ivar_index]
                        print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {}\033[0m".format(ivar)
                        result[ivar] = backtrace_variable(method, idx, ivar)
                        if param_list[param_index] in ('J', 'D'):
                            ivar_index += 2
                        else:
                            ivar_index += 1
                        param_index += 1

                    return result
                elif ins.get_name() in ("check-cast", "if-eqz", "if-nez", "if-lt", "if-gez"):
                    print WARN_MSG_PREFIX + "\033[1;30m{:04x} {:20s} {} --- continue\033[0m".format(idx, ins.get_name(), ins.get_output())
                    continue
                else:
                    print WARN_MSG_PREFIX + "\033[0;31m\t\tWhat? Instruction No Define:{} {}\033[0m".format(ins.get_name(), ins.get_output())
                    write_log_to_file('command_not_found', "{} / {}\n".format(ins.get_name(), ins.get_output()))

        # result not found in current_block
        # push previous blocks to stack
        previous_blocks = current_block.get_prev()
        print WARN_MSG_PREFIX + "\033[1;30mFind {:d} Prev Block(s)\033[0m".format(len(previous_blocks))
        for block in current_block.get_prev():
            if not traced_block.has_key(block[2]):
                stack.append(block[2])
                traced_block[block[2]] = True

        # pop one block to process
        if len(stack) > 0:
            print WARN_MSG_PREFIX + "\033[1;30mPop From Stack\033[0m"
            current_block = stack.pop(0)
            address_list  = list(block_address_list[current_block])
            ins_index_in_block = current_block.get_nb_instructions()
        else:
            print WARN_MSG_PREFIX + "\033[1;30mNo Prev Block\033[0m"
            return None

    print "\tFound {}".format(result)
    print ""

def get_instruction_by_idx(method, target_idx):
    # find query instruction position
    idx = 0
    blocks = method.get_basic_blocks().get()
    for block in blocks:
        instructions = block.get_instructions()
        for index in range(0, len(instructions)):
            ins = instructions[index]
            if idx == target_idx:
                return ins
            idx += ins.get_length()

if __name__ == "__main__" :
    # load apk and analyze
    a, d, dx = read_apk("apk/tunein.player.apk")
    cm = d.get_class_manager()

    # search ContentResolver.query()
    query_paths = dx.tainted_packages.search_methods("^Landroid/content/ContentResolver;$", "^query$", ".")
    print "Found %d path(s)." % len(query_paths)

    # prepare regular expression
    re_skip_class = re.compile('Landroid|Lcom/google')

    for i in range(0, len(query_paths)):
        path = query_paths[i]
        print "Path {:2d}".format(i)

        # get analyzed method
        analyzed_method = get_analyzed_method_from_path(path)
        method = analyzed_method.get_method()

        # print source class & method name
        print "\tClass  {0}".format(method.get_class_name())
        print "\tMethod {0}".format(method.get_name())
        print "\tOffset 0x{0:04x}".format(path.get_idx())

        # skip built-in library
        if re_skip_class.match(method.get_class_name()):
            print "Skip {}".format(method.get_class_name())
            continue

        # get variable name
        target_ins = get_instruction_by_idx(analyzed_method, path.get_idx())
        uri_variable = get_instruction_variable(target_ins)[1]

        # backtrace variable
        result = backtrace_variable(analyzed_method, path.get_idx(), uri_variable)
        print_backtrace_result(result)
        print_backtrace_result(result, 0)
