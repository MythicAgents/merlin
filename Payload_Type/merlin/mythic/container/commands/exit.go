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
	"encoding/json"
	"fmt"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// exit creates and return a Mythic Command structure that is registered with the Mythic server.
// This command instructs the Merlin Agent to quit running and exit.
func exit() structs.Command {
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
		CommandAttributes:              structs.CommandAttribute{},
		CommandParameters:              nil,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      exitCreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}
	return command
}

// exitCreateTask task a Mythic Task and converts into a Merlin Job that that is encoded into JSON and subsequently sent to the Merlin Agent
func exitCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID

	job := jobs.Command{
		Command: task.Task.CommandName,
		Args:    []string{},
	}

	jobBytes, err := json.Marshal(job)
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error JSON marshalling the Merlin jobs.Job structure: %s", err)
		resp.Success = false
		return
	}

	mythicJob := Job{
		Type:    jobs.CONTROL,
		Payload: string(jobBytes),
	}
	mythicJobBytes, err := json.Marshal(mythicJob)
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error JSON marshalling the Job structure: %s", err)
		resp.Success = false
		return
	}
	task.Args.SetManualArgs(string(mythicJobBytes))

	resp.Success = true

	return
}
