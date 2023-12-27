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
	"fmt"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message/jobs"
)

// ifconfig creates and return a Mythic Command structure that is registered with the Mythic server that subsequently
// instructs the Merlin Agent to enumerate that network interfaces and return the information
func ifconfig() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS, structs.SUPPORTED_OS_LINUX, structs.SUPPORTED_OS_MACOS},
	}
	command := structs.Command{
		Name:                           "ifconfig",
		NeedsAdminPermissions:          false,
		HelpString:                     "ifconfig",
		Description:                    "Enumerates a list of all network interfaces",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            nil,
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              nil,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      ifconfigCreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     nil,
		TaskFunctionParseArgDictionary: nil,
		TaskCompletionFunctions:        nil,
	}
	return command
}

// ifconfigCreateTasking task a Mythic Task and converts into a Merlin Job that that is encoded into JSON and subsequently sent to the Merlin Agent
func ifconfigCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID

	job := jobs.Command{
		Command: task.Task.CommandName,
		Args:    []string{},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.NATIVE)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/ifconfig/ifconfigCreateTasking(): %s", err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)
	resp.Success = true

	return
}
