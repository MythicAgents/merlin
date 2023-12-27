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

// ja3 is a command to instruct the Merlin Agent to use a TLS client derived from the input JA3 string to communicate with the server.
func ja3() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS, structs.SUPPORTED_OS_LINUX, structs.SUPPORTED_OS_MACOS},
	}

	ja3string := structs.CommandParameter{
		Name:                                    "ja3string",
		ModalDisplayName:                        "JA3 String",
		CLIName:                                 "ja3string",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The JA3 \"string\" that the client should use",
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
		Name:                           "ja3",
		NeedsAdminPermissions:          false,
		HelpString:                     "ja3 <ja3string>",
		Description:                    "Instruct the agent to use a client derived from the input JA3 string to communicate with the server.\nWARNING: Make sure the server can support the client configuration",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            nil,
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              []structs.CommandParameter{ja3string},
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      ja3CreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// ja3CreateTasking takes a Mythic Task and converts into a Merlin Job for the JA3 command that is encoded into JSON and subsequently sent to the Merlin Agent
func ja3CreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID

	v, err := task.Args.GetArg("ja3string")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"ja3string\" argument's value for the \"ja3\" command: %s", err)
		resp.Success = false
		return
	}
	ja3string := v.(string)

	job := jobs.Command{
		Command: "ja3",
		Args:    []string{ja3string},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.CONTROL)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/ja3/ja3CreateTasking(): %s", err)
		resp.Success = false
		return
	}
	task.Args.SetManualArgs(mythicJob)
	resp.DisplayParams = &ja3string
	resp.Success = true

	return
}
