#!/usr/bin/env python3

import lldb
import optparse
import shlex

already = {}

def bp(frame, bp_loc, internal_dict):
	global f
	global dbg
	global tgt
	global already

#	dbg.SetAsync(False)
	tgt.GetProcess().Stop()
	name = frame.GetFunctionName()
	symbol = frame.GetSymbol()
	modul = frame.GetModule()
	fn = modul.GetSymbolAtIndex(0).GetStartAddress().__str__()
	if (fn.startswith("GLUT") == False):
		return False
	if (name in already):
		return False
	already[name] = True
		
#	g = dbg.GetOutputFileHandle()
#	dbg.SetOutputFileHandle(f, True)
#	dbg.HandleCommand("disassemble -n " + name)
#	dbg.SetOutputFileHandle(g,True)
	f.write("void* " + name + "() {\n")
	#f.flush()
	func = frame.GetFunction()
	#for i in func.GetInstructions(tgt):
	#	f.write(i)
	#f.write(symbol.__str__() + "\n")
	for i in symbol.GetInstructions(tgt):
		lab = i.GetAddress().__str__().split("+")
		if (len(lab) > 1):
			lab = "L" + lab[len(lab)-1].strip() + ":\t"
		else:
			lab = "L0:\t"
		f.write(lab)
	#	f.write(i.GetAddress().__str__() + ":\t")
		f.write(i.GetMnemonic(tgt) + " ")
		f.write(i.GetOperands(tgt) + " ; ")
		f.write(i.GetComment(tgt) + "\n")
	#	f.write(i.__str__() + "\n")
		if (i.GetMnemonic(tgt) == "callq"):
			loc = i.GetOperands(tgt)
			if (loc[0] == "*"):
				loc = i.GetComment(tgt)
				if (len(loc) > 1 and "symbol stub" not in loc
					and "objc_"not in loc):
					loc = loc.split(":")[0]
					loc = loc.split(")")[1]
				else:
					loc = ""
			else:
				if ("symbol stub" in i.GetComment(tgt)):
					loc = ""

			if (len(loc) > 1 and loc not in already):
				print(loc)
				already[loc] = True
				brp = tgt.BreakpointCreateByAddress(
					int(loc.strip(), 0))
			#		lldb.SBAddress(int(loc.strip(), 0), tgt))
				brp.SetScriptCallbackFunction("trace.bp")
	f.write("} // end of "+ name + "\n\n")
	f.flush()
	tgt.GetProcess().Continue()
	return False


def trace(debugger: lldb.SBDebugger, command: str, result: lldb.SBCommandReturnObject, internal_dict):
	# debugger.HandleCommand("breakpoint set --func-regex='.*' -s GLUT")
	debugger.HandleCommand("breakpoint set --func-regex='.*' -s GLUT")
	debugger.HandleCommand('breakpoint command add -F trace.bp')
	debugger.SetAsync(False)
	global f
	f = open("log.txt", "w")
	return

def __lldb_init_module(debugger, internal_dict):
	global dbg
	global tgt
	dbg = debugger
	tgt = dbg.GetSelectedTarget()
	debugger.HandleCommand('command script add -f trace.trace trace')

