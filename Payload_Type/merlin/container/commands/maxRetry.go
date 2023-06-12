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

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// maxRetry is a command to instruct the Merlin Agent to use a TLS client derived from the input JA3 string to communicate with the server.
func maxRetry() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS, structs.SUPPORTED_OS_LINUX, structs.SUPPORTED_OS_MACOS, "Debian"},
	}

	max := structs.CommandParameter{
		Name:                                    "maxretry",
		ModalDisplayName:                        "Max Retry",
		CLIName:                                 "maxretry",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_NUMBER,
		Description:                             "The maximum amount of times the Agent can fail to check in before it quits running",
		Choices:                                 nil,
		DefaultValue:                            7,
		SupportedAgents:                         nil,
		SupportedAgentBuildParameters:           nil,
		ChoicesAreAllCommands:                   false,
		ChoicesAreLoadedCommands:                false,
		FilterCommandChoicesByCommandAttributes: nil,
		DynamicQueryFunction:                    nil,
		ParameterGroupInformation: []structs.ParameterGroupInfo{
			{
				ParameterIsRequired:   true,
				GroupName:             "Default",
				UIModalPosition:       0,
				AdditionalInformation: nil,
			},
		},
	}

	command := structs.Command{
		Name:                           "maxretry",
		NeedsAdminPermissions:          false,
		HelpString:                     "maxretry <number>",
		Description:                    "The maximum amount of time the Agent can fail to check in before it quits running",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            nil,
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              []structs.CommandParameter{max},
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      maxRetryCreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// maxRetryCreateTasking takes a Mythic Task and converts into a Merlin Job for the JA3 command that is encoded into JSON and subsequently sent to the Merlin Agent
func maxRetryCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID

	max, err := task.Args.GetNumberArg("maxretry")
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/maxRetry/maxRetryCreateTask(): %s", err)
		resp.Success = false
		return
	}

	job := jobs.Command{
		Command: "maxretry",
		Args:    []string{fmt.Sprintf("%d", int(max))},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.CONTROL)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/ja3/ja3CreateTasking(): %s", err)
		resp.Success = false
		return
	}
	task.Args.SetManualArgs(mythicJob)

	disp := fmt.Sprintf("%d", int(max))
	resp.DisplayParams = &disp
	resp.Success = true

	return
}
