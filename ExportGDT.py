# Creates or Adds data to a Ghidra Data Type (GDT) archive for the current program
# @author 13laze/austinc3030
# @menupath Tools.Data Types.ExportGDT
# @category Data Types

import os

from ghidra.util import Msg
from ghidra.program.model.data import FileDataTypeManager
from ghidra.app.script import GhidraScript
from ghidra.app.cmd.function import CaptureFunctionDataTypesCmd
from docking.widgets.filechooser import GhidraFileChooser
from ghidra.util.task import TaskMonitor

# For exporting a ghidra data type archive for the current program,
# specify a new file that does not exist. For adding to an existing
# ghidra data type archive (creating a library of sorts), specify an
# existing ghidra data type archive.
gdt = askFile('GDT Archive File', 'OK')

if os.path.isfile(str(gdt)):
    dtm = FileDataTypeManager.openFileArchive(gdt, True)
else:
    dtm = FileDataTypeManager.createFileArchive(gdt)
cmd = CaptureFunctionDataTypesCmd(dtm, currentProgram.getMemory(), None)
cmd.applyTo(currentProgram, TaskMonitor.DUMMY)

dtm.save()
dtm.close()