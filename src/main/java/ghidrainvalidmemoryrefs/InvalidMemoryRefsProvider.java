package ghidrainvalidmemoryrefs;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.widgets.table.GTableFilterPanel;
import ghidra.app.context.ProgramActionContext;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import resources.ResourceManager;

public class InvalidMemoryRefsProvider extends ComponentProviderAdapter {

	private JPanel mainPanel;
	private InvalidMemoryRefsModel tableModel;
	private GTableFilterPanel<Reference> filterPanel;

	public InvalidMemoryRefsProvider(GhidraInvalidMemoryRefsPlugin plugin) {
		super(plugin.getTool(), "Invalid Memory References", plugin.getName(), ProgramActionContext.class);

		setIcon(ResourceManager.loadImage("images/table-warning.png"));
		mainPanel = buildMainPanel();
		addToToolbar();
		addToTool();
	}

	private JPanel buildMainPanel() {
		JPanel memPanel = new JPanel(new BorderLayout());

		tableModel = new InvalidMemoryRefsModel();

		GhidraTable table = new GhidraTable(tableModel);
		table.setActionsEnabled(true);
		table.installNavigation(tool);

		filterPanel = new GhidraTableFilterPanel<>(table, tableModel);

		memPanel.add(new JScrollPane(table), BorderLayout.CENTER);
		memPanel.add(filterPanel, BorderLayout.SOUTH);

		return memPanel;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void setProgram(Program program) {
		tableModel.setProgram(program);
	}

	void dispose() {
		removeFromTool();
		filterPanel.dispose();
		tool = null;
	}
}
