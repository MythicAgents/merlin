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

// cd creates and return a Mythic Command structure that is registered with the Mythic server
// This command is instructs the Merlin Agent to change it's current working directory to the one provided
func cd() structs.Command {
	command := structs.Command{
		Name:                           "cd",
		NeedsAdminPermissions:          false,
		HelpString:                     "cd <path>",
		Description:                    "Change the agent's current working directory",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{"T1005"},
		ScriptOnlyCommand:              false,
		CommandAttributes:              structs.CommandAttribute{},
		CommandParameters:              nil,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      cdCreateTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// cdCreateTask task a Mythic Task and converts into a Merlin Job that that is encoded into JSON and subsequently sent to the Merlin Agent
func cdCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID
	/*
		What Merlin gets from Mythic
		{
			"action":"get_tasking",
			"padding":"Sb",
			"tasks":[
				{
					"timestamp":1678920007,
					"command":"cd",
					"parameters":"/home/rastley/Downloads",
					"id":"28c242ef-97fe-4074-84de-4d5e40056f4f"
				}
			]
		}

		// The JSON object above is unmarshalled into this structure only used by the Mythic client in Merlin
		// through the convertToMerlinMessage() function
		// Merlin Agent ignores the Command field except for SOCKS messages
		type Task struct {
			ID      string  `json:"id"`
			Command string  `json:"command"`
			Params  string  `json:"parameters"`
			Time    float64 `json:"timestamp"`
		}

		The task params needs to be a JSON object that matches this Job structure
			The Job.Type directly relates to Merlin job types like CMD, CONTROL, or NATIVE
			The Job.Payload needs to be a JSON object that unmarshalled in to corresponding Merlin structure


		// The Task structure's Params field from above is JSON unmarshalled into this Job structure in the convertTasksToJobs() function
		// Job is a structure used only by the Mythic client in Merlin
		type Job struct {
			Type    int    `json:"type"`
			Payload string `json:"payload"`
		}

		// The Job structure's Payload field from above is JSON unmarshalled into this Command structure in the convertTasksToJobs() function
		// Command is the structure to send a task for the agent to execute
		type Command struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		}
	*/

	job := jobs.Command{
		Command: task.Task.CommandName,
		Args:    []string{task.Task.Params},
	}

	jobBytes, err := json.Marshal(job)
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error JSON marshalling the Merlin jobs.Job structure: %s", err)
		resp.Success = false
		return
	}

	mythicJob := Job{
		Type:    jobs.NATIVE,
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
