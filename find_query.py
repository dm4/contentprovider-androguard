#!/usr/bin/env python

from androguard.core.bytecodes import dvm, apk
from androguard.core.analysis import analysis
import androlyze
import os, re

apk_name = "apk/tunein.player.apk"
apk_basename = os.path.basename(apk_name)
apk_session_name = "session/" + apk_basename

# mkdir session
if not os.path.isdir("session"):
    os.system("mkdir session")

# check if session saved
if not os.path.isfile(apk_session_name):
    a = apk.APK(apk_name)
    d = dvm.DalvikVMFormat(a.get_dex())
    dx = analysis.VMAnalysis(d)
    # save session
    androlyze.save_session([a, d, dx], apk_session_name)
else:
    # load session
    a, d, dx = androlyze.load_session(apk_session_name)

# search ContentResolver.query()
query_paths = dx.tainted_packages.search_methods("^Landroid/content/ContentResolver;$", "^query$", ".")
print "Found %d path(s)." % len(query_paths)

# prepare regular expression
re_skip_class = re.compile('Landroid|Lcom/google')

i = 0
for path in query_paths:
    print "Path %2d" % i
    i += 1

    # get source class & method name
    cm = d.get_class_manager()
    method = cm.get_method_ref(path.src_idx)
    src_class_name, src_method_name, src_descriptor = method.get_class_name(), method.get_name(), method.get_descriptor()
    dst_class_name, dst_method_name, dst_descriptor = method.get_class_name(), method.get_name(), method.get_descriptor()
    print "\tClass  {0}".format(src_class_name)
    print "\tMethod {0}".format(src_method_name)
    print "\tOffset 0x{0:04x}".format(path.get_idx())

    if re_skip_class.match(src_class_name):
        continue

    # get analyized method
    analyized_method = dx.get_method(d.get_method_descriptor(src_class_name, src_method_name, src_descriptor))

    #
    idx = 0
    blocks = analyized_method.get_basic_blocks().get()
    for block in blocks:
        instructions = block.get_instructions()
        for index in range(0, len(instructions)):
            ins = instructions[index]
            if idx == path.get_idx():
                query_index = index
                query_block = block
                # v0 ... v5, Landroid/content/ContentResolver;->query(...
                #     - split by ' ' to get first 'v0'
                #     - substring [1:] get '0'
                #     - convert to interge, + 1, add 'v' at begining
                uri_variable = 'v' + str(int(ins.get_output().split(' ')[0][1:])+1)
                print "\t", idx, ins.get_output()
            idx += ins.get_length()

    # get the instruction where uri_variable is set
    found_ins = None
    while found_ins == None:
        instructions = query_block.get_instructions()
        re_uri_variable = re.compile(uri_variable)
        for index in range(query_index - 1, -1, -1):
            ins = instructions[index]
            if re_uri_variable.match(ins.get_output()):
                found_ins = ins.get_name() + " " + ins.get_output()
                break;
        if found_ins == None:
            print i
            query_block = query_block.get_prev()[0]

    print found_ins

#        print "\t %s %x %x" % (i.name, i.start, i.end), '[ NEXT = ', ', '.join( "%x-%x-%s" % (j[0], j[1], j[2].get_name()) for j in i.get_next() ), ']', '[ PREV = ', ', '.join( j[2].get_name() for j in i.get_prev() ), ']'
#
#        for ins in i.get_instructions():
#            print "\t\t %x" % idx, ins.get_name(), ins.get_output()
#            idx += ins.get_length()
#
#        print ""
