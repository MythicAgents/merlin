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

// uptime creates and return a Mythic Command structure that is registered with the Mythic server
func uptime() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS},
	}

	command := structs.Command{
		Name:                           "uptime",
		NeedsAdminPermissions:          false,
		HelpString:                     "uptime",
		Description:                    "Use the Windows API GetTickCount64 method to determine how long the host has been running.",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              nil,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      uptimeCreateTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// uptimeCreateTask takes a Mythic Task and converts into a Merlin Job that is encoded into JSON and subsequently sent to the Merlin Agent
func uptimeCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/uptime/uptimeCreateTask()"
	resp.TaskID = task.Task.ID

	job := jobs.Command{
		Command: task.Task.CommandName,
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.MODULE)
	if err != nil {
		resp.Error = fmt.Sprintf("%s: %s", pkg, err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)

	resp.Success = true
	return
}
