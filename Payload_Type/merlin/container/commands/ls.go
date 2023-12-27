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

// ls creates and return a Mythic Command structure that is registered with the Mythic server
func ls() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS, structs.SUPPORTED_OS_LINUX, structs.SUPPORTED_OS_MACOS},
	}

	path := structs.CommandParameter{
		Name:                                    "path",
		ModalDisplayName:                        "Path",
		CLIName:                                 "path",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The directory path to list the contents of",
		Choices:                                 nil,
		DefaultValue:                            ".",
		SupportedAgents:                         nil,
		SupportedAgentBuildParameters:           nil,
		ChoicesAreAllCommands:                   false,
		ChoicesAreLoadedCommands:                false,
		FilterCommandChoicesByCommandAttributes: nil,
		DynamicQueryFunction:                    nil,
		ParameterGroupInformation: []structs.ParameterGroupInfo{
			{
				ParameterIsRequired:   false,
				GroupName:             "Default",
				UIModalPosition:       0,
				AdditionalInformation: nil,
			},
		},
	}

	command := structs.Command{
		Name:                           "ls",
		NeedsAdminPermissions:          false,
		HelpString:                     "ls <directory path>",
		Description:                    "Use Golang native commands to list a directory's contents",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{"T1083"},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              []structs.CommandParameter{path},
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      lsCreateTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// lsCreateTask takes a Mythic Task and converts into a Merlin Job that is encoded into JSON and subsequently sent to the Merlin Agent
func lsCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID

	path, err := task.Args.GetStringArg("path")
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/ls/lsCreateTask(): %s", err)
		resp.Success = false
		return
	}
	if path == "" {
		path = "."
	}

	job := jobs.Command{
		Command: task.Task.CommandName,
		Args:    []string{path},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.NATIVE)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/ls/lsCreateTask(): %s", err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)

	resp.DisplayParams = &path
	resp.Success = true

	return
}
