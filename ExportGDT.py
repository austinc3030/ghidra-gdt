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
from java.io import File

# For exporting a ghidra data type archive for the current program,
# specify a new file that does not exist. For adding to an existing
# ghidra data type archive (creating a library of sorts), specify an
# existing ghidra data type archive.
gdt_dir = askString('GDT Archive Directory', 'OK')
gdt_filename = askString('GDT Archive Filename', 'OK')
gdt_filepath = str(os.path.join(gdt_dir, gdt_filename))
gdt_file = File(gdt_filepath)

dtm = FileDataTypeManager.createFileArchive(gdt_file)
cmd = CaptureFunctionDataTypesCmd(dtm, currentProgram.getMemory(), None)
cmd.applyTo(currentProgram, TaskMonitor.DUMMY)

dtm.save()
dtm.close()