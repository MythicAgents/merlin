/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 3 of the License, or any later version.

Merlin is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package commands

import (
	// Standard
	"fmt"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message/jobs"
)

func listAssembly() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS},
	}

	command := structs.Command{
		Name:                           "list-assembly",
		NeedsAdminPermissions:          false,
		HelpString:                     "list-assembly",
		Description:                    "List the .NET assemblies that have been loaded in the default AppDomain in the Agent's process.",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            nil,
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              nil,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      listAssemblyCreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     nil,
		TaskFunctionParseArgDictionary: nil,
		TaskCompletionFunctions:        nil,
	}
	return command
}

func listAssemblyCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID

	job := jobs.Command{
		Command: "clr",
		Args:    []string{"list-assemblies"},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.MODULE)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/exit/exitCreateTasking(): %s", err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)

	resp.Success = true

	return

}
