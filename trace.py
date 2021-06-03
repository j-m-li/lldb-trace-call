#!/usr/bin/env python3
# 
# The author disclaims copyright to this source code.
#

import lldb
import optparse
import shlex
import os

already = {}

def findv(id):
	error = lldb.SBError()
	for thread in tgt.GetProcess():
		for frame in thread:
			var = lldb.macosx.heap.find_variable_containing_address(
                    		False, frame, id)
			if var:
				return var.__str__()
	v = tgt.ResolveLoadAddress(id)
	for sy in v.GetModule():
		if (sy.GetStartAddress().GetLoadAddress(tgt) >= id
			and sy.GetEndAddress().GetLoadAddress(tgt) <= id
			):
			return sy.__str__()
	b = "{" 
	for i in range(0,8):
	 	b = b + "0x" + f'{(tgt.GetProcess().ReadUnsignedFromMemory(id + i, 1, error)):02x}' + ","
	return b + "}"
	
def dumpr(frame):
	for grp in frame.GetRegisters():
		for reg in grp:
			if ((grp.GetName() == "General Purpose Registers"
				and reg.GetTypeName() == "unsigned long"
				and reg.GetName() != "cs"
				and reg.GetName() != "rflags"
				) 
				# and
				#reg.GetValue() > 0 and
				# and reg.IsSynthetic()
				# reg.IsInScope()
				):
				id = reg.GetValueAsUnsigned(lldb.LLDB_INVALID_ADDRESS)
				des = ""
				ch = tgt.GetBasicType(lldb.eBasicTypeChar)
				if id != lldb.LLDB_INVALID_ADDRESS:
					v = tgt.ResolveLoadAddress(id)
					des = v.GetSymbol().GetName()
					error = lldb.SBError()
					if len(des or "") < 1 and id > 0:
						try:
							des = tgt.GetProcess().ReadUnsignedFromMemory(id, 1, error)
						#	des = '"' + tgt.GetProcess().ReadCStringFromMemory(id, 4096, lldb.SBError()).replace('\\', '\\\\').replace('"', '\\"')  + '"'
						except:
							des = ""
						else:
							#stm = lldb.SBStream()
							#des = v.GetValue().GetObjectDescription()
							#v.GetDescription(stm)
							#des = stm.GetData()
							#des = v.GetSymbol().__str__()
							if error.Success():
								des = tgt.CreateValueFromAddress("n", v, tgt.GetBasicType(lldb.eBasicTypeChar).GetPointerType()).__str__()#GetObjectDescription()
							else:
								des = ""
							if '""' in des:
								try:
									import json

									des = json.dumps(tgt.GetProcess().ReadCStringFromMemory(id, 4096, lldb.SBError()))
								except:
									des = ""
									des = findv(id) 
								#	des = v.GetModule().ResolveSymbolContextForAddress(v, lldb.eSymbolContextBlock).__str__()
				rei = reg.GetName()
				if (rei == "rip"):
					des = ""
				if len(des or "") < 2 or ord(des[1]) < 10 :
					if (rei == "rax"
						or rei == "rdi"
						or rei == "rsi"
						or rei == "rdx"
						or rei == "rcx"
						or rei == "r8"
						or rei == "r9"
						or rei == "r10"
						or rei == "rip"
						):
						des = "0x" + f'{id:016x}'
					
				#des =  str(reg.GetObjectDescription() or "")
				#des =  str(reg.GetChildAtIndex(0).__str__() or "")
				if (len(des or "") > 0):
					import xml.sax.saxutils 
					trc.write("\t" + reg.GetName() + "=\"")
					trc.write(xml.sax.saxutils.escape(des, {'"': "&quot;"}) + "\"\n")


def ret_bp(frame, bp_loc, internal_dict):
	trc.write("</")
	fun = already["0x" + f'{bp_loc.GetAddress().GetLoadAddress(tgt):x}']
	trc.write(fun.strip()
		.replace('-', '_') 
		.replace('[', '_') 
		.replace(']', '_') 
		.replace('+', '_') 
		.replace('@', '_') 
		.replace(' ', '_') 
		.replace('*', '_') 
		.replace('%', '_') 
		.replace(':', '_') 
		)
	trc.write(">\n")
	return False

def sub_bp(frame, bp_loc, internal_dict):
	tgt.GetProcess().Stop()
	symbol = frame.GetSymbol()
	trc.write("<")
	ad = frame.GetPCAddress()
	#trc.write(ad.__str__() + ":\n")
	#trc.write(bp_loc.__str__() + "+\n")
	#trc.flush()
	fun = already["0x" + f'{bp_loc.GetAddress().GetLoadAddress(tgt):x}']
	fun = fun.split(':')
	if (len(fun) > 1):
		fun = fun[1]
	else:		
		fun = fun[0]
	trc.write(fun.strip()
		.replace('-', '_') 
		.replace('[', '_') 
		.replace(']', '_') 
		.replace('+', '_') 
		.replace('@', '_') 
		.replace(' ', '_') 
		.replace('*', '_') 
		.replace('%', '_') 
		.replace(':', '_') 
		+ "\n\n")

	dumpr(frame)
	trc.write("/>\n\n")
	tgt.GetProcess().Continue()
	return False

def bp(frame, bp_loc, internal_dict):
	global f
	global dbg
	global tgt
	global already

#	dbg.SetAsync(False)
#	tgt.GetProcess().Stop()
	name = frame.GetFunctionName()
	symbol = frame.GetSymbol()
	trc.write("<")
	fun = symbol.GetName()
	trc.write(fun.strip()
		.replace('-', '_') 
		.replace('[', '_') 
		.replace(']', '_') 
		.replace('+', '_') 
		.replace('@', '_') 
		.replace(' ', '_') 
		.replace('*', '_') 
		.replace('%', '_') 
		.replace(':', '_') 
		+ "\n\n")


	dumpr(frame)
	trc.write(">\n")
	modul = frame.GetModule()
	fn = modul.GetSymbolAtIndex(0).GetStartAddress().__str__()
	if (fn.startswith("GLUT") == False):
		return False
	if (name in already):
		return False
	already[name] = True
	if len(already) == 1:
		for sy in modul:
			f.write(sy.__str__() +  "\n\n")
			
	r = open("raw/" + name + ".bin", "wb")
			
	s.write("retdec-decompiler.py -a x86-64 --raw-entry-point 0"
		+ " -m raw -e little "
		+ "--backend-call-info-obtainer pessim "
		+ "--raw-section-vma "
		)
	s.write(hex(frame.GetPC()))

	s.write(" \"raw/" + name + ".bin\"\n")
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
		k = i.GetData(tgt).GetByteSize()
		j = 0
		while (j < k):
			r.write(i.GetData(tgt).GetUnsignedInt8(
				lldb.SBError(), j).to_bytes(1, 'little'));
			j = j + 1
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
					# and "objc_"not in loc
					):
					loc = loc.split(":")[0]
					loc = loc.split(")")[1]
					loc = "0x" + f'{int(loc, 0):x}'
				else:
					loc = ""
			else:
				None
				#if ("symbol stub" in i.GetComment(tgt)):
				#	loc = ""

			loc = "0x" + f'{int(i.GetAddress().GetLoadAddress(tgt)):x}'
			if (len(loc) > 1 and loc not in already):
				print(loc)
				already[loc] = i.GetComment(tgt) 
				if len(already[loc]) < 1:
					already[loc] = i.GetOperands(tgt) 
					
				brp = tgt.BreakpointCreateByAddress(
					int(loc.strip(), 0))
				brp.SetScriptCallbackFunction("trace.sub_bp")
		if (i.GetMnemonic(tgt) == "retq"
			or i.GetMnemonic(tgt) == "ud2"
			):
			loc = "0x" + f'{int(i.GetAddress().GetLoadAddress(tgt)):x}'
			if (len(loc) > 1 and loc not in already):
				already[loc] = name 
				brp = tgt.BreakpointCreateByAddress(
					int(loc.strip(), 0))
				brp.SetScriptCallbackFunction("trace.ret_bp")
	f.write("} // end of "+ name + "\n\n")
	f.flush()
	s.flush()
	r.close()
#	tgt.GetProcess().Continue()
	return False


def trace(debugger: lldb.SBDebugger, command: str, result: lldb.SBCommandReturnObject, internal_dict):
	# debugger.HandleCommand("breakpoint set --func-regex='.*' -s GLUT")
	debugger.HandleCommand("breakpoint set --func-regex='.*' -s GLUT")
	debugger.HandleCommand('breakpoint command add -F trace.bp')
	debugger.SetAsync(False)
	global f
	f = open("log.txt", "w")
	global trc
	trc = open("trace.xml", "w")
	trc.write("<root>\n")
	global s
	s = open("decompile.sh", "w")
	try:
		os.mkdir("raw")
	except:
		None
	listener = lldb.SBListener('my listener')
	tgt.GetBroadcaster().AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
	tgt.Launch(listener, None, None, 
		"/dev/null",
		None,
		None,
		os.getcwd(),
		0,
		False,
		lldb.SBError())
	event = lldb.SBEvent()
	while True:
		if listener.WaitForEventForBroadcasterWithType(5,
                            tgt.GetBroadcaster(),
                            lldb.SBProcess.eBroadcastBitStateChanged,
                            event):
			st = tgt.GetProcess().GetState()
			if st == lldb.eStateStopped:
				tgt.GetProcess().Continue()
			if not tgt.GetProcess().is_alive:
				trc.write("</root>\n")
				return
	return

def __lldb_init_module(debugger, internal_dict):
	global dbg
	global tgt
	dbg = debugger
	tgt = dbg.GetSelectedTarget()
	debugger.HandleCommand('command script add -f trace.trace trace')
	debugger.HandleCommand('script import lldb.macosx.heap')

	return
