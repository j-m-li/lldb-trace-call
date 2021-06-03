from  ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# get the current program
# here currentProgram is predefined

program = currentProgram
decompinterface = DecompInterface()
decompinterface.openProgram(program);
functions = program.getFunctionManager().getFunctions(True)
symbols = program.getSymbolTable()
af = program.getAddressFactory()
a = af.getAddress("0x07e20")
a0 = af.getAddress("0x0")
affff = af.getAddress("0x00007fff553191ac")
symbols.createLabel(a, "main", ghidra.program.model.symbol.SourceType.USER_DEFINED)
#symbols.createLabel(0x888, "main", ghidra.program.model.Symbol.USER_DEFINED)
rip = program.getRegister("RIP")
proco = program.getProgramContext()
#proco.setValue(rip, a0, affff, 0x00007fff553191ac)

for function in list(functions):
    print(function)
    # decompile each function
    tokengrp = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
    print(tokengrp.getDecompiledFunction().getC())

