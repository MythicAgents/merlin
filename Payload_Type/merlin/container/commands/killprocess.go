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
	"strconv"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message/jobs"
)

// killProcess returns a Mythic Command structure that is registered with the Mythic server that subsequently instructs the
// Merlin Agent to kill a running process by its Process ID (PID)
func killProcess() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS, structs.SUPPORTED_OS_LINUX, structs.SUPPORTED_OS_MACOS},
	}

	pid := structs.CommandParameter{
		Name:                                    "pid",
		ModalDisplayName:                        "Process ID",
		CLIName:                                 "pid",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The Process ID (PID) you want to kill",
		Choices:                                 nil,
		DefaultValue:                            nil,
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
		Name:                           "killprocess",
		NeedsAdminPermissions:          false,
		HelpString:                     "killprocess <PID>",
		Description:                    "Kill a running process by its Process ID (PID)",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            nil,
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              []structs.CommandParameter{pid},
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      killprocessCreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}
	return command
}

// killprocessCreateTasking takes a Mythic Task and converts into a Merlin Job that that is encoded into JSON and subsequently sent to the Merlin Agent
func killprocessCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID

	v, err := task.Args.GetArg("pid")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"pid\" argument's value for the \"killprocess\" command: %s", err)
		resp.Success = false
		return
	}
	pid := v.(string)

	// Make sure a number was provided
	_, err = strconv.Atoi(pid)
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error converting the \"pid\" to an integer for the \"killprocess\" command: %s", err)
		resp.Success = false
		return
	}

	job := jobs.Command{
		Command: task.Task.CommandName,
		Args:    []string{pid},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.NATIVE)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/killprocessCreateTasking/killprocessCreateTasking(): %s", err)
		resp.Success = false
		return
	}
	task.Args.SetManualArgs(mythicJob)

	resp.DisplayParams = &pid
	resp.Success = true

	return
}
