package ghidrainvalidmemoryrefs;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.AbstractGTableModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.table.ProgramTableModel;

public class InvalidMemoryRefsModel extends AbstractGTableModel<Reference> implements ProgramTableModel {

	private List<ReferenceCol> columns = new ArrayList<>();
	private List<Reference> rowDataList = new ArrayList<>();
	private Program program;
	protected FunctionManager funcMgr;

	InvalidMemoryRefsModel() {
		columns.add(new ReferencedAddressColumn());
		columns.add(new ReferenceTypeColumn());
		columns.add(new SourceAddressColumn());
		columns.add(new SourceFunctionColumn());
	}

	private void updateModelData() {
		rowDataList = new ArrayList<>();
		InstructionIterator instrIter = program.getListing().getInstructions(true);
		while (instrIter.hasNext()) {
			Instruction instr = instrIter.next();
			Reference[] refs = instr.getReferencesFrom();
			for (Reference ref : refs) {
				Address dest = ref.getToAddress();
				if (!program.getMemory().contains(dest) && !dest.isStackAddress()) {
					rowDataList.add(ref);
				}
			}
		}
		fireTableDataChanged();
	}

	void setProgram(Program program) {
		this.program = program;
		this.funcMgr = program.getFunctionManager();
		updateModelData();
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public String getName() {
		return "Invalid Memory Refs";
	}

	@Override
	public List<Reference> getModelData() {
		return rowDataList;
	}

	@Override
	public int getColumnCount() {
		return columns.size();
	}

	@Override
	public String getColumnName(int column) {
		return columns.get(column).getName();
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return columns.get(columnIndex).getColumnClass();
	}

	@Override
	public Object getColumnValueForRow(Reference t, int columnIndex) {
		return columns.get(columnIndex).getValueForRow(rowDataList, t);
	}

	@Override
	public ProgramLocation getProgramLocation(int modelRow, int modelColumn) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ProgramSelection getProgramSelection(int[] modelRows) {
		// TODO Auto-generated method stub
		return null;
	}

	private abstract class ReferenceCol {
		private String name;
		private Class<?> classType;

		ReferenceCol(String name, Class<?> classType) {
			this.name = name;
			this.classType = classType;
		}

		public String getName() {
			return name;
		}

		public Class<?> getColumnClass() {
			return classType;
		}

		protected abstract Object getValueForRow(List<Reference> data, Reference t);
	}

	private class ReferencedAddressColumn extends ReferenceCol {
		ReferencedAddressColumn() {
			super("Referenced Addr", Address.class);
		}

		@Override
		protected Object getValueForRow(List<Reference> data, Reference t) {
			return t.getToAddress();
		}
	}

	private class ReferenceTypeColumn extends ReferenceCol {
		ReferenceTypeColumn() {
			super("Type", String.class);
		}

		@Override
		protected Object getValueForRow(List<Reference> data, Reference t) {
			return t.getReferenceType().getDisplayString();
		}
	}

	private class SourceAddressColumn extends ReferenceCol {
		SourceAddressColumn() {
			super("Source Addr", Address.class);
		}

		@Override
		protected Object getValueForRow(List<Reference> data, Reference t) {
			return t.getFromAddress();
		}
	}

	private class SourceFunctionColumn extends ReferenceCol {
		SourceFunctionColumn() {
			super("Caller func", Function.class);
		}

		@Override
		protected Object getValueForRow(List<Reference> data, Reference t) {
			return funcMgr.getFunctionContaining(t.getFromAddress());
		}
	}
}
