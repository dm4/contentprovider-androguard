#!/usr/bin/env python

from androguard.core.bytecodes import dvm, apk
from androguard.core.analysis import analysis
from androguard.decompiler.dad import decompile
import androlyze
from androlyze import *
import os, re
import json

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
        # check params J or D
        # by atdog
        num_params = 0
        for p in params:
            if p in ('J', 'D'):
                num_params += 2
            else:
                num_params +=1
        return [ "v{:d}".format(i) for i in range(0, nb - num_params) ], [ "v{:d}".format(i) for i in range(nb - num_params, nb) ]
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
    elif type(ins) == type([]):
        print indent + "----------" + "Multi Path Start" + "----------"
        is_first = True
        for ins_dict in ins:
            if is_first:
                is_first = False
            else:
                print indent + "---"
            _print_backtrace_result(ins_dict, depth + 1)
        print indent + "----------" + "Multi Path Done" + "----------"
    elif isinstance(ins, Instruction):
        print OK_MSG_PREFIX + indent + "{:16s}{}".format(ins.get_name(), ins.get_output())
        var_list = [ var for var in result.keys() if var != 'ins' ]
        for var in var_list:
            print OK_MSG_PREFIX + indent + var
            _print_backtrace_result(result[var], depth + 1)
    else:
        print "Parsing Error: " + str(ins)

def _print_backtrace_result_decompile(result):
    ins = result["ins"]
    if type(ins) == type('str'):
        return ins
    elif isinstance(ins, Instruction):
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
        elif ins.get_name() in ("const-string", "const/4"):
            return ins.get_output().split(', ')[-1]
        elif ins.get_name() == "const-class":
            # trim the Lclass_name;
            class_name = ins.get_output().split(', ')[-1][1:-1]
            return "{}".format(class_name)
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
    else:
        print "Parsing Error!"
        return "PARSE_ERROR"

def print_backtrace_result(result, decompile=1):
    if decompile == 1:
        print OK_MSG_PREFIX + "Result: {}".format(_print_backtrace_result_decompile(result))
    else:
        _print_backtrace_result(result, 0);

def create_method_exception_link(method):
    # create link between blocks base on exception
    #     by atdog
    global method_exceptions_link_done_list
    if method not in method_exceptions_link_done_list:
        blocks_list = method.get_basic_blocks().gets()
        bb = method.get_basic_blocks()
        for e in method.exceptions.gets():
#             buff = "%x:%x\n" % (e.start, e.end)
            raise_exception_block = bb.get_basic_block(e.start)

            child_blocks_idx_list = []
            for i in e.exceptions :
                child_blocks_idx_list.append(i[1])
#                 buff += "\t(%s -> %x)\n" % (i[0], i[1])
            raise_exception_block.set_childs(child_blocks_idx_list)
#             print buff
        method_exceptions_link_done_list.append(method)

def backtrace_variable(method, ins_addr, var, enable_multi_caller_path = 1, jump_list = [], method_depth = 10):
    # check traced_vars
    global traced_vars
    traced_key = "{} {} {} {} {} {}".format(method.get_method().get_class_name(), method.get_method().get_name(), method.get_method().get_descriptor(), ins_addr, var, enable_multi_caller_path)
    if traced_vars.has_key(traced_key):
        print "Read '{}' from traced_vars".format(traced_key)
        return traced_vars[traced_key]

    create_method_exception_link(method)

    # too deep
    depth = len(jump_list)
    if depth >= method_depth:
        print 'TOO_DEEP'
        for jump_method in jump_list:
            print jump_method
        return {"ins": "TOO_DEEP"}

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

        # get all subclasses
        all_subclasses = []
        queue = []
        queue.append(method.get_method().get_class_name())
        while len(queue) > 0:
            c = queue.pop()
            if c in all_subclasses:
                continue
            else:
                all_subclasses.append(c)
                if class_hierarchy.has_key(c):
                    for subc in class_hierarchy[c]:
                        queue.append(subc)
        print "all_subclasses: " + str(all_subclasses)

        # find all caller path
        caller_paths = []
        for c in all_subclasses:
            for path in dx.tainted_packages.search_methods("^{}$".format(c), "^{}$".format(method.get_method().get_name()), "^{}$".format(descriptor)):
                # skip self call loop
                src_class_name, src_method_name, src_descriptor = path.get_src(cm)
                if src_class_name == c and src_method_name == method.get_method().get_name() and src_descriptor == method.get_method().get_descriptor():
                    continue
                caller_paths.append(path)

        # add link from intent / service
        if intent_service_link is not None:
            intent_service_key = "{} {} {}".format(method.get_method().get_class_name(), method.get_method().get_name(), method.get_method().get_descriptor())
            if intent_service_link.has_key(intent_service_key):
                for path in intent_service_link[intent_service_key]:
                    print "Found Path From Link"
                    caller_paths.append(path)

        # find no caller
        if len(caller_paths) == 0:
            print WARN_MSG_PREFIX + "\033[0;31mNO ONE CALL YOU\033[0m"
            write_log_to_file('no_one_call_you', "{} / {} / {}\n".format(method.get_method().get_class_name(), method.get_method().get_name(), method.get_method().get_descriptor()))
            return {"ins": "null"}

        # find the paths
        result = {}
        result["ins"] = []
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
            if target_ins.get_name() in ("invoke-direct", "invoke-virtual", "invoke-super", "invoke-virtual/range", "invoke-direct/range", "invoke-super/range"):
                target_var = target_var_list[target_param_index + 1]
            elif target_ins.get_name() in ("invoke-static", "invoke-static/range"):
                target_var = target_var_list[target_param_index]
            else:
                print WARN_MSG_PREFIX + '\033[0;31mNOT IMPLEMENT YET: {}\033[0m'.format(target_ins.get_name())
            print WARN_MSG_PREFIX + "\033[1;30mFind {}\033[0m".format(target_var)

            # print
            src_class_name, src_method_name, src_descriptor = path.get_src(cm)
            print "Want {}, From {} {} {} To {} {} {}, Find {}".format(var, method.get_method().get_class_name(), method.get_method().get_name(), method.get_method().get_descriptor(), src_class_name, src_method_name, src_descriptor, target_var)

            # recursive find the result
            jump_list.append("{} / {} / {}".format(method.get_method().get_class_name(), method.get_method().get_name(), method.get_method().get_descriptor()))
            r = backtrace_variable(analyzed_method, path.get_idx(), target_var, enable_multi_caller_path, jump_list)
            if r is not None:
                if enable_multi_caller_path:
                    result["ins"].append(r)
                else:
                    return r
            jump_list.pop()
        return result

    # prepare regular expression
    re_var = re.compile(var + '([^0-9a-zA-Z_]|$)')
    re_op_if = re.compile("^if(-.*)?$")
    re_op_iget = re.compile("^iget(-.*)?$")
    re_op_sget = re.compile("^sget(-.*)?$")
    re_op_aget = re.compile("^aget(-.*)?$")
    re_op_iput = re.compile("^iput(-.*)?$")
    re_op_sput = re.compile("^sput(-.*)?$")
    re_op_aput = re.compile("^aput(-.*)?$")
    re_op_const = re.compile("^const((-|/).*)?$")
    re_op_typetotype = re.compile("^.*-to-.*$")

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
                if re_op_const.match(ins.get_name()) or re_op_sget.match(ins.get_name()) or ins.get_name() in ("new-instance"):
                    print WARN_MSG_PREFIX + "\033[1;30mFound {}\033[0m".format(var)
                    result = {"ins": ins}

                    print "Write '{}' to traced_vars".format(traced_key)
                    traced_vars[traced_key] = result

                    return result
                elif re_op_typetotype.match(ins.get_name()) or re_op_aget.match(ins.get_name()) or re_op_iget.match(ins.get_name()) or ins.get_name() in ("move", "move/from16", "move-wide", "move-wide/from16", "move-object", "move-object/from16", "new-array", "array-length"):
                    print WARN_MSG_PREFIX + "\033[1;30mFound {}\033[0m".format(var)
                    ivar_list = get_instruction_variable(ins)

                    # check target var is the first var in the instruction
                    if ivar_list[0] == var:
                        result = {"ins": ins}

                        # backtrace other var in the instruction
                        for i in range(1, len(ivar_list)):
                            ivar = ivar_list[i]
                            print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {} {} {} {}\033[0m".format(method.get_method().get_class_name(), method.get_method().get_name(), method.get_method().get_descriptor() , ivar)
                            result[ivar] = backtrace_variable(method, idx, ivar, enable_multi_caller_path, jump_list)

                        # save to traced_vars
                        print "Write '{}' to traced_vars".format(traced_key)
                        traced_vars[traced_key] = result

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
                    if ins.get_name() in ("invoke-static", "invoke-static/range"):
                        ivar_index = 0
                    else:
                        ivar_index = 1
                        ivar = ivar_list[0]
                        print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {} {} {} {}\033[0m".format(method.get_method().get_class_name(), method.get_method().get_name(), method.get_method().get_descriptor() , ivar)
                        result[ivar] = backtrace_variable(method, idx, ivar, enable_multi_caller_path, jump_list)

                    param_index = 0
                    while ivar_index < len(ivar_list):
                        ivar = ivar_list[ivar_index]
                        print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {} {} {} {}\033[0m".format(method.get_method().get_class_name(), method.get_method().get_name(), method.get_method().get_descriptor() , ivar)
                        result[ivar] = backtrace_variable(method, idx, ivar, enable_multi_caller_path, jump_list)

                        if param_list[param_index] in ('J', 'D'):
                            ivar_index += 2
                        else:
                            ivar_index += 1
                        param_index += 1

                    # save to traced_vars
                    print "Write '{}' to traced_vars".format(traced_key)
                    traced_vars[traced_key] = result

                    return result
                elif ins.get_name() in ("invoke-direct", "invoke-direct/range", "invoke-virtual", "invoke-virtual/range", "invoke-static", "invoke-static/range", "invoke-interface", "invoke-interface/range", "invoke-super", "invoke-super/range"):
                    ivar_list = get_instruction_variable(ins)
                    result = {"ins": ins}

                    # backtrace all other vars in the instruction
                    #     - aware: long(J)/double(D) will have two register
                    param_list = get_invoke_info(ins.get_output())[2]
                    if ins.get_name() in ("invoke-static", "invoke-static/range"):
                        ivar_index = 0
                    else:
                        ivar_index = 1
                        ivar = ivar_list[0]
                        print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {} {} {} {}\033[0m".format(method.get_method().get_class_name(), method.get_method().get_name(), method.get_method().get_descriptor() , ivar)
                        result[ivar] = backtrace_variable(method, idx, ivar, enable_multi_caller_path, jump_list)

                    param_index = 0
                    while ivar_index < len(ivar_list):
                        ivar = ivar_list[ivar_index]
                        print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {} {} {} {}\033[0m".format(method.get_method().get_class_name(), method.get_method().get_name(), method.get_method().get_descriptor() , ivar)
                        result[ivar] = backtrace_variable(method, idx, ivar, enable_multi_caller_path, jump_list)

                        if param_list[param_index] in ('J', 'D'):
                            ivar_index += 2
                        else:
                            ivar_index += 1
                        param_index += 1

                    # save to traced_vars
                    print "Write '{}' to traced_vars".format(traced_key)
                    traced_vars[traced_key] = result

                    return result
                elif ins.get_name() in ("div-long", "div-long/2addr", "add-int/lit8", "add-int", "mul-int/2addr", "sub-long", "add-int/2addr", "mul-int/lit16", "rem-int/lit8", "add-long/2addr", "add-int/lit16", "div-int/lit8", "sub-int", "or-int/2addr", "or-int/lit8", "rem-int/2addr", "mul-double/2addr", "mul-long/2addr", "div-float/2addr", "add-double/2addr", "mul-double"):
                    ivar_list = get_instruction_variable(ins)
                    result = {"ins": ins}
                    print WARN_MSG_PREFIX + "\033[1;30mFound {}\033[0m".format(var)

                    # backtrace other var in the instruction
                    for i in range(1, len(ivar_list)):
                        ivar = ivar_list[i]
                        print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {} {} {} {}\033[0m".format(method.get_method().get_class_name(), method.get_method().get_name(), method.get_method().get_descriptor() , ivar)
                        result[ivar] = backtrace_variable(method, idx, ivar, enable_multi_caller_path, jump_list)

                    # save to traced_vars
                    print "Write '{}' to traced_vars".format(traced_key)
                    traced_vars[traced_key] = result

                    return result
                # Exception
                #    [*] 0480 move-exception       v23
                #    [*] 0492 invoke-virtual/range v23, Lorg/apache/http/client/HttpResponseException;->getStatusCode()I
                elif ins.get_name() == "move-exception":
                    result = {"ins": ins}
                    print WARN_MSG_PREFIX + "\033[1;30mFound {}\033[0m".format(var)

                    # save to traced_vars
                    print "Write '{}' to traced_vars".format(traced_key)
                    traced_vars[traced_key] = result

                    return result
                # aput-object v0, v1, v2 => v2[v1] = v0
                # if -> "^if(-.*)?$"
                # ignore all xput-*
                elif re_op_if.match(ins.get_name()) or re_op_iput.match(ins.get_name()) or re_op_aput.match(ins.get_name()) or re_op_sput.match(ins.get_name()) or ins.get_name() in ("check-cast", "packed-switch", "monitor-enter"):
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

def construct_class_hierarchy():
    result = {}
    all_classes = d.get_classes()
    for c in all_classes:
        class_name = c.get_name()
        superclass_name = c.get_superclassname()
        if not result.has_key(superclass_name):
            result[superclass_name] = []
        result[superclass_name].append(class_name)
    return result

def get_intentclass_from_backtrace_result(result):
    json_result = _get_intentclass_from_backtrace_result(result)
    if json_result in ("null", "TOO_DEEP"):
        json_result = "{}"
    else:
        json_result = "{" + json_result[:-1] + "}"
    print json_result
    return json.loads(json_result)

def _get_intentclass_from_backtrace_result(result):
    """
        return {
            action:,
            package:,
            class:
        }
    """
    ins = result['ins']
    if type(ins) == type('str'):
        return ""
    elif isinstance(ins, Instruction):
        var_list = get_instruction_variable(ins)
        if ins.get_name() in ("invoke-virtual", "invoke-direct"):
            _, method_name, method_param_list = get_invoke_info(ins.get_output())
            r = ""
            if method_name == "setPackage":
                r = '"package":"'
                r += _get_intentclass_from_backtrace_result(result[var_list[-1]])
                r += '",'
            elif method_name == "setAction":
                r = '"action":"'
                r += _get_intentclass_from_backtrace_result(result[var_list[-1]])
                r += '",'
            elif method_name == "setClassName" and method_param_list[0] == "Ljava/lang/String;" and method_param_list[1] == "Ljava/lang/String;":
                r = '"package":"'
                r += _get_intentclass_from_backtrace_result(result[var_list[-2]])
                r += '",'
                r += '"class":"'
                r += _class_to_java_format(_get_intentclass_from_backtrace_result(result[var_list[-1]]))
                r += '",'
            elif method_name == "<init>" and len(method_param_list) > 0 and method_param_list[-1] == "Ljava/lang/String;":
                r = '"action":"'
                r += _get_intentclass_from_backtrace_result(result[var_list[-1]])
                r += '",'
            elif method_name == "<init>" and len(method_param_list) > 1 and method_param_list[-1] == "Ljava/lang/Class;":
                r = '"class":"'
                r += _class_to_java_format(_get_intentclass_from_backtrace_result(result[var_list[-1]]))
                r += '",'
            r += _get_intentclass_from_backtrace_result(result[var_list[0]])
            return r
        elif ins.get_name() in ("const-string", "const-class"):
            return ins.get_output().split(', ')[-1][1:-1]
        else:
            return ""
    else:
        return "null"

def _class_to_java_format(class_name):
    re_var = re.compile('^L.*;$')
    if not re_var.match(class_name):
        class_name = 'L' + class_name.replace(".","/") + ';'
    return '{}'.format(class_name)

def find_service_method(json_result, service = "service"):
    json_keys_list = json_result.keys()
    class_name = None
    if json_result.has_key("class"):
        class_name = json_result['class'].encode()
    elif json_result.has_key("action"):
        action_name = json_result['action'].encode()
        target_method = None

        xml = a.xml['AndroidManifest.xml']
        for item in xml.getElementsByTagName("service") :
            for i in item.getElementsByTagName("action"):
                if action_name == i.getAttribute("android:name"):
                    class_name = _class_to_java_format(item.getAttribute("android:name"))
                    break
    else:
        return "None"

    for method in d.get_methods():
        if method.get_class_name() == class_name:
            if service == "service":
                if method.get_name() == "onHandleIntent":
                    return method
                elif method.get_name() == "onStartCommand":
                    return method
                else:
                    continue
            else:
                if method.get_name() == "onReceive":
                    return method
        else:
            continue

def broadcast_link():
    paths = dx.tainted_packages.search_methods("^Landroid/content/Context;$", "^sendBroadcast$", "^\(Landroid/content/Intent;( .*\)V)?")

    service_result = {}
    for i in range(0, len(paths)):
        path = paths[i]
        print OK_MSG_PREFIX + "broadcast link path {}".format(i)
        # get analyzed method
        analyzed_method = get_analyzed_method_from_path(path)
        method = analyzed_method.get_method()

        # print source class & method name
        print OK_MSG_PREFIX + "Class  {0}".format(method.get_class_name())
        print OK_MSG_PREFIX + "Method {0}".format(method.get_name())
        print OK_MSG_PREFIX + "Descriptor {0}".format(method.get_descriptor())
        print OK_MSG_PREFIX + "Offset 0x{0:04x}".format(path.get_idx())

        # get variable name
        target_ins = get_instruction_by_idx(analyzed_method, path.get_idx())
        intent_variable = get_instruction_variable(target_ins)[1]

        print WARN_MSG_PREFIX + target_ins.get_name(), target_ins.get_output()
        print WARN_MSG_PREFIX, get_instruction_variable(target_ins)

        print WARN_MSG_PREFIX, intent_variable
        result = backtrace_variable(analyzed_method, path.get_idx(), intent_variable, 0, [])
#        print_backtrace_result(result, 0)
#        print_backtrace_result(result)
        json_result = get_intentclass_from_backtrace_result(result)

        m = find_service_method(json_result, "broadcast")
        if str(type(m)) == "<type 'instance'>":
            if "{} {} {}".format(m.get_class_name(), m.get_name(), m.get_descriptor()) not in service_result.keys():
                service_result["{} {} {}".format(m.get_class_name(), m.get_name(), m.get_descriptor())] = []
#            service_result["{} {} {}".format(m.get_class_name(), m.get_name(), m.get_descriptor())].append({"idx" : path.get_idx(), "mx" : analyzed_method})
            service_result["{} {} {}".format(m.get_class_name(), m.get_name(), m.get_descriptor())].append(path)

        print WARN_MSG_PREFIX + "--------------------------------------------------"
    return service_result

def service_link():
    paths = dx.tainted_packages.search_methods("^Landroid/content/Context;$", "^startService$", "^\(Landroid/content/Intent;\)Landroid/content/ComponentName;$")

    service_result = {}
    for i in range(0, len(paths)):
        path = paths[i]
        print OK_MSG_PREFIX + "service link path {}".format(i)
        # get analyzed method
        analyzed_method = get_analyzed_method_from_path(path)
        method = analyzed_method.get_method()

        # print source class & method name
        print OK_MSG_PREFIX + "Class  {0}".format(method.get_class_name())
        print OK_MSG_PREFIX + "Method {0}".format(method.get_name())
        print OK_MSG_PREFIX + "Descriptor {0}".format(method.get_descriptor())
        print OK_MSG_PREFIX + "Offset 0x{0:04x}".format(path.get_idx())

        # get variable name
        target_ins = get_instruction_by_idx(analyzed_method, path.get_idx())
        intent_variable = get_instruction_variable(target_ins)[1]

        print WARN_MSG_PREFIX + target_ins.get_name(), target_ins.get_output()
        print WARN_MSG_PREFIX, get_instruction_variable(target_ins)

        print WARN_MSG_PREFIX, intent_variable
        result = backtrace_variable(analyzed_method, path.get_idx(), intent_variable, 0, [])
#        print_backtrace_result(result, 0)
#        print_backtrace_result(result)
        json_result = get_intentclass_from_backtrace_result(result)

        m = find_service_method(json_result)
        if str(type(m)) == "<type 'instance'>":
            if "{} {} {}".format(m.get_class_name(), m.get_name(), m.get_descriptor()) not in service_result.keys():
                service_result["{} {} {}".format(m.get_class_name(), m.get_name(), m.get_descriptor())] = []
#            service_result["{} {} {}".format(m.get_class_name(), m.get_name(), m.get_descriptor())].append({"idx" : path.get_idx(), "mx" : analyzed_method})
            service_result["{} {} {}".format(m.get_class_name(), m.get_name(), m.get_descriptor())].append(path)

        print WARN_MSG_PREFIX + "--------------------------------------------------"
    return service_result

def get_target_methods(level = 0, class_name = "^Landroid/content/ContentResolver;$", method_name = "^query$", descriptor = "^(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;$"):
    if level >= 4:
        return []
    level += 1

    descriptor = descriptor.replace('(', '\(').replace(')', '\)').replace('[', '\[').replace(']', '\]')
    print 'dx.tainted_packages.search_methods("{}", "{}", "{}")'.format(class_name, method_name, descriptor)
    paths = dx.tainted_packages.search_methods(class_name, method_name, descriptor)

    target_methods = []
    for i in range(0, len(paths)):
        path = paths[i]
        print OK_MSG_PREFIX + "target method {}".format(i)
        # get analyzed method
        analyzed_method = get_analyzed_method_from_path(path)
        method = analyzed_method.get_method()

        # print source class & method name
        print OK_MSG_PREFIX + "Class  {0}".format(method.get_class_name())
        print OK_MSG_PREFIX + "Method {0}".format(method.get_name())
        print OK_MSG_PREFIX + "Descriptor {0}".format(method.get_descriptor())

        target_methods.append("{}->{}{}".format(method.get_class_name(), method.get_name(), method.get_descriptor()))

        target_methods += get_target_methods(level, "^{}$".format(method.get_class_name()), "^{}$".format(method.get_name()), "^{}$".format(method.get_descriptor()))

        print WARN_MSG_PREFIX + "--------------------------------------------------"
    return target_methods

def check_target_in_result(target_methods, result, ins_stack = []):
    ins = result["ins"]
    if type(ins) == type('str'):
        pass
    elif type(ins) == type([]):
        for ins_dict in ins:
            if check_target_in_result(target_methods, ins_dict, ins_stack) == 1:
                return 1
    elif isinstance(ins, Instruction):
        ins_stack.append(ins)
        if "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;" in ins.get_output():
            print "Target Found: query()"
            for i in ins_stack:
                print "{} {}".format(i.get_name(), i.get_output())
            return 1
        for method in target_methods:
            if method in ins.get_output():
                print "Target Found:", method
                for i in ins_stack:
                    print "{} {}".format(i.get_name(), i.get_output())
                return 1
        var_list = [ var for var in result.keys() if var != 'ins' ]
        for var in var_list:
            if check_target_in_result(target_methods, result[var], ins_stack) == 1:
                return 1
        ins_stack = ins_stack[:-1]
    else:
        print "Parsing Error: " + str(ins)
    return 0

# save traced vars
traced_vars = {}
method_exceptions_link_done_list = []

if __name__ == "__main__" :
    # load apk and analyze
#    a, d, dx = read_apk("apk/tunein.player.apk")
    a, d, dx = read_apk("apk/com.texty.sms-1.apk")
    cm = d.get_class_manager()

    # construct class hierarchy
    class_hierarchy = construct_class_hierarchy()
#    print class_hierarchy

    # construct intent / service link
    intent_service_link = None
    broadcast_link = None
    intent_service_link = service_link()
    broadcast_link = broadcast_link()
    print intent_service_link
    print broadcast_link

    # combine
    intent_service_link = dict(intent_service_link.items() + broadcast_link.items())

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
        print "\tDesc   {0}".format(method.get_descriptor())
        print "\tOffset 0x{0:04x}".format(path.get_idx())

        # skip built-in library
        if re_skip_class.match(method.get_class_name()):
            print "Skip {}".format(method.get_class_name())
            continue

        # get variable name
        target_ins = get_instruction_by_idx(analyzed_method, path.get_idx())
        uri_variable = get_instruction_variable(target_ins)[1]

        # backtrace variable
        result = backtrace_variable(analyzed_method, path.get_idx(), uri_variable, 1, [])
        print_backtrace_result(result, 0)
#        print_backtrace_result(result)
