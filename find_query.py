#!/usr/bin/env python

from androguard.core.bytecodes import dvm, apk
from androguard.core.analysis import analysis
from androguard.decompiler.dad import decompile
import androlyze
import os, re

apk_session_dir = "session/"

def read_apk(apk_name):
    """ Read apk file and return a, d, dx """
    apk_basename = os.path.basename(apk_name)
    apk_session_name = apk_session_dir + apk_basename

    # mkdir session
    if not os.path.isdir(apk_session_dir):
        os.system("mkdir", apk_session_dir)

    # check if session saved
    if not os.path.isfile(apk_session_name):
        a, d, dx = AnalyzeAPK(apk_name)
        androlyze.save_session([a, d, dx], apk_session_name)
    else:
        a, d, dx = androlyze.load_session(apk_session_name)

    return a, d, dx

def get_variable_list(method):
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


if __name__ == "__main__" :
    # load apk and analyze
    a, d, dx = read_apk("apk/tunein.player.apk")

    # search ContentResolver.query()
    query_paths = dx.tainted_packages.search_methods("^Landroid/content/ContentResolver;$", "^query$", ".")
    print "Found %d path(s)." % len(query_paths)

    # prepare regular expression
    re_skip_class = re.compile('Landroid|Lcom/google')

    i = 0
    for path in query_paths:
        print "Path {:2d}".format(i)
        i += 1

        # get source class & method name
        cm = d.get_class_manager()
    #    method = cm.get_method_ref(path.src_idx)
        src_class_name, src_method_name, src_descriptor = path.get_src(cm)
        dst_class_name, dst_method_name, dst_descriptor = path.get_dst(cm)
        print "\tClass  {0}".format(src_class_name)
        print "\tMethod {0}".format(src_method_name)
        print "\tOffset 0x{0:04x}".format(path.get_idx())

        if re_skip_class.match(src_class_name):
            continue

        # get analyzed method
        method = d.get_method_descriptor(src_class_name, src_method_name, src_descriptor)
        analyzed_method = dx.get_method(method)
        print get_variable_list(method)

        # decompile to get source code
#        decompiled_method = decompile.DvMethod(analyzed_method)
#        decompiled_method.process()
#        print decompiled_method.get_source()

        # find query instruction position
        idx = 0
        blocks = analyzed_method.get_basic_blocks().get()
        for block in blocks:
            instructions = block.get_instructions()
            for index in range(0, len(instructions)):
                ins = instructions[index]
                if idx == path.get_idx():
                    query_index = index
                    query_block = block
                    # get uri parameter
                    #
                    # v0 ... v5, Landroid/content/ContentResolver;->query(...
                    #     - split by ' ' to get first 'v0'
                    #     - substring [1:] get '0'
                    #     - convert to interge then + 1
                    #     - add 'v' at begining
                    uri_variable = 'v' + str(int(ins.get_output().split(' ')[0][1:])+1)
                    # print
                    # print "\t", idx, ins.get_name(), ins.get_output()
                idx += ins.get_length()

        # back trace to get the instruction where uri_variable is set
        print "\tStart back tracing...";
        found_ins = None
        while found_ins == None:
            instructions = query_block.get_instructions()
            re_uri_variable = re.compile(uri_variable)
            for index in range(query_index - 1, -1, -1):
                ins = instructions[index]
                if re_uri_variable.match(ins.get_output()):
                    # print
                    print "\t\t" + ins.get_name() + " " + ins.get_output()
                    #
                    if ins.get_name() == "sget-object":
                        found_ins = ins.get_name() + " " + ins.get_output()
                    elif ins.get_name() == "move-result-object":
                        index -= 1
                        ins = instructions[index]
                        found_ins = ins.get_name() + " " + ins.get_output()
                    else:
                        found_ins = ins.get_name() + " " + ins.get_output()
                    break;
            if found_ins == None:
                print "!"
                query_block = query_block.get_prev()[0]

        print "\tFound URI {}".format(found_ins)
        print ""

#        print "\t %s %x %x" % (i.name, i.start, i.end), '[ NEXT = ', ', '.join( "%x-%x-%s" % (j[0], j[1], j[2].get_name()) for j in i.get_next() ), ']', '[ PREV = ', ', '.join( j[2].get_name() for j in i.get_prev() ), ']'
#        for ins in i.get_instructions():
#            print "\t\t %x" % idx, ins.get_name(), ins.get_output()
#            idx += ins.get_length()
#        print ""
