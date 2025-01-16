/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidrainvalidmemoryrefs;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * <CODE>GhidraInvalidMemoryRefsPlugin</CODE> displays a list of invalid memory
 * references all across a program. This is useful when reversing firmware or
 * drivers for determining memory mappings.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Invalid memory references view",
	description = "List any references to undefined memory addresses.",
	servicesRequired = { GoToService.class },
	eventsProduced = { ProgramLocationPluginEvent.class }
)
//@formatter:on
public class GhidraInvalidMemoryRefsPlugin extends ProgramPlugin implements DomainObjectListener {

	private InvalidMemoryRefsProvider provider;
	private GoToService goToService;

	public GhidraInvalidMemoryRefsPlugin(PluginTool tool) {
		super(tool);

		provider = new InvalidMemoryRefsProvider(this);
	}

	@Override
	protected void init() {
		goToService = tool.getService(GoToService.class);
		if (currentProgram != null) {
			programActivated(currentProgram);
		}
	}

	/**
	 * Subclass should override this method if it is interested in open program
	 * events.
	 */
	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
		provider.setProgram(program);
	}

	/**
	 * Subclass should override this method if it is interested in close program
	 * events.
	 */
	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
		provider.setProgram(null);
	}

	/**
	 * This is the callback method for DomainObjectChangedEvents.
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (provider == null || !provider.isVisible()) {
			return;
		}
		// TODO: Notify the provider to update...
	}

	/**
	 * Called when a memory location line is selected in the IvalidMemoryRefsDialog.
	 */
	void invalidRefSelected(Address addr) {
		ProgramLocation loc = new ProgramLocation(currentProgram, addr);
		goToService.goTo(loc);
	}

	/**
	 * Tells a plugin that it is no longer needed. The plugin should remove itself
	 * from anything that it is registered to and release any resources.
	 */
	@Override
	public void dispose() {
		if (provider != null) {
			provider.dispose();
			provider = null;
		}
		if (currentProgram != null) {
			currentProgram.removeListener(this);
			currentProgram = null;
		}
		super.dispose();
	}

}
