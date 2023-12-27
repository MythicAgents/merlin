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

// makeToken creates and return a Mythic Command structure that is registered with the Mythic server
func makeToken() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS},
	}

	user := structs.CommandParameter{
		Name:                                    "user",
		ModalDisplayName:                        "Username",
		CLIName:                                 "user",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "Domain and username to make a token for (e.g. ACME\\RASTLEY",
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

	pass := structs.CommandParameter{
		Name:                                    "pass",
		ModalDisplayName:                        "Password",
		CLIName:                                 "pass",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The account's plain-text password",
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
				UIModalPosition:       1,
				AdditionalInformation: nil,
			},
		},
	}

	command := structs.Command{
		Name:                  "make_token",
		NeedsAdminPermissions: false,
		HelpString:            "make_token <DOMAIN\\Username> <password>",
		Description: "Create a new type-9 logon session and Windows access token for the provided" +
			" credentials. The token is only used for NETWORK authentication, not local.",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{"T1134.003"},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              []structs.CommandParameter{user, pass},
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      makeTokenCreateTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// makeTokenCreateTask takes a Mythic Task and converts into a Merlin Job that is encoded into JSON and subsequently sent to the Merlin Agent
func makeTokenCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID

	user, err := task.Args.GetStringArg("user")
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/makeToken/makeTokenCreateTask(): %s", err)
		resp.Success = false
		return
	}

	pass, err := task.Args.GetStringArg("pass")
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/makeToken/makeTokenCreateTask(): %s", err)
		resp.Success = false
		return
	}

	job := jobs.Command{
		Command: "token",
		Args:    []string{"make", user, pass},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.MODULE)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/makeToken/makeTokenCreateTask(): %s", err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)

	disp := fmt.Sprintf("%s %s", user, pass)
	resp.DisplayParams = &disp
	resp.Success = true

	return
}
