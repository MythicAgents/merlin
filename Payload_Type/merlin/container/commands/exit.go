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

// exit creates and return a Mythic Command structure that is registered with the Mythic server.
// This command instructs the Merlin Agent to quit running and exit.
func exit() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS, structs.SUPPORTED_OS_LINUX, structs.SUPPORTED_OS_MACOS},
	}

	command := structs.Command{
		Name:                           "exit",
		NeedsAdminPermissions:          false,
		HelpString:                     "exit",
		Description:                    "Instruct the agent to quit running and exit",
		Version:                        0,
		SupportedUIFeatures:            []string{"callback_table:exit"},
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              nil,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      exitCreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     nil,
		TaskFunctionParseArgDictionary: nil,
		TaskCompletionFunctions:        nil,
	}
	return command
}

// exitCreateTask takes a Mythic Task and converts into a Merlin Job that that is encoded into JSON and subsequently sent to the Merlin Agent
func exitCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID

	job := jobs.Command{
		Command: task.Task.CommandName,
		Args:    []string{},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.CONTROL)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/exit/exitCreateTasking(): %s", err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)

	resp.Success = true

	return
}
