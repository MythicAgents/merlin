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
	"strings"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message/jobs"
)

// token creates and return a Mythic Command structure that is registered with the Mythic server
func token() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS},
	}

	method := structs.CommandParameter{
		Name:                                    "method",
		ModalDisplayName:                        "Method",
		CLIName:                                 "method",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
		Description:                             "The \"method\" to interact with Windows access tokens",
		Choices:                                 []string{"make", "privs", "rev2self", "steal", "whoami"},
		DefaultValue:                            "whoami",
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

	args := structs.CommandParameter{
		Name:                                    "arguments",
		ModalDisplayName:                        "Arguments",
		CLIName:                                 "args",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "Arguments that are specific to the selected token method",
		Choices:                                 nil,
		DefaultValue:                            "",
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
				UIModalPosition:       1,
				AdditionalInformation: nil,
			},
		},
	}

	pid := structs.CommandParameter{
		Name:                                    "pid",
		ModalDisplayName:                        "Process ID",
		CLIName:                                 "pid",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_NUMBER,
		Description:                             "The process ID to interact with",
		Choices:                                 nil,
		DefaultValue:                            0,
		SupportedAgents:                         nil,
		SupportedAgentBuildParameters:           nil,
		ChoicesAreAllCommands:                   false,
		ChoicesAreLoadedCommands:                false,
		FilterCommandChoicesByCommandAttributes: nil,
		DynamicQueryFunction:                    nil,
		ParameterGroupInformation: []structs.ParameterGroupInfo{
			{
				ParameterIsRequired:   true,
				GroupName:             "Steal Token",
				UIModalPosition:       1,
				AdditionalInformation: nil,
			},
		},
	}

	tokenPID := structs.CommandParameter{
		Name:                                    "token-pid",
		ModalDisplayName:                        "Process ID",
		CLIName:                                 "token-pid",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_NUMBER,
		Description:                             "The process ID to interact with",
		Choices:                                 nil,
		DefaultValue:                            0,
		SupportedAgents:                         nil,
		SupportedAgentBuildParameters:           nil,
		ChoicesAreAllCommands:                   false,
		ChoicesAreLoadedCommands:                false,
		FilterCommandChoicesByCommandAttributes: nil,
		DynamicQueryFunction:                    nil,
		ParameterGroupInformation: []structs.ParameterGroupInfo{
			{
				ParameterIsRequired:   false,
				GroupName:             "Token Privs",
				UIModalPosition:       1,
				AdditionalInformation: nil,
			},
		},
	}

	user := structs.CommandParameter{
		Name:                                    "username",
		ModalDisplayName:                        "Username",
		CLIName:                                 "username",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "Domain and username to make a token for (e.g. ACME\\\\RASTLEY",
		Choices:                                 nil,
		DefaultValue:                            "",
		SupportedAgents:                         nil,
		SupportedAgentBuildParameters:           nil,
		ChoicesAreAllCommands:                   false,
		ChoicesAreLoadedCommands:                false,
		FilterCommandChoicesByCommandAttributes: nil,
		DynamicQueryFunction:                    nil,
		ParameterGroupInformation: []structs.ParameterGroupInfo{
			{
				ParameterIsRequired:   true,
				GroupName:             "Make Token",
				UIModalPosition:       1,
				AdditionalInformation: nil,
			},
		},
	}

	pass := structs.CommandParameter{
		Name:                                    "password",
		ModalDisplayName:                        "Password",
		CLIName:                                 "password",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The account's plain-text password",
		Choices:                                 nil,
		DefaultValue:                            "",
		SupportedAgents:                         nil,
		SupportedAgentBuildParameters:           nil,
		ChoicesAreAllCommands:                   false,
		ChoicesAreLoadedCommands:                false,
		FilterCommandChoicesByCommandAttributes: nil,
		DynamicQueryFunction:                    nil,
		ParameterGroupInformation: []structs.ParameterGroupInfo{
			{
				ParameterIsRequired:   true,
				GroupName:             "Make Token",
				UIModalPosition:       2,
				AdditionalInformation: nil,
			},
		},
	}

	params := []structs.CommandParameter{method, args, pid, tokenPID, user, pass}
	command := structs.Command{
		Name:                  "token",
		NeedsAdminPermissions: false,
		HelpString:            "token <method>",
		Description: "\"Interact with Windows access tokens." +
			"Use the \"Make Token\" parameter group to create a new access token." +
			"Use the \"Steal Token\" parameter group to steal an access token." +
			"Use the \"Token Privs\" parameter group to view a token's privileges." +
			"The \"Default\" parameter group can be used to interact with ANY method.",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{"T1134"},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              params,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      tokenCreateTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// tokenCreateTask takes a Mythic Task and converts into a Merlin Job that is encoded into JSON and subsequently sent to the Merlin Agent
func tokenCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/token/tokenCreateTask()"
	resp.TaskID = task.Task.ID

	method, err := task.Args.GetStringArg("method")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the \"method\" argument %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	args, err := task.Args.GetStringArg("arguments")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the \"arguments\" argument %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	pid, err := task.Args.GetNumberArg("pid")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the \"pid\" argument %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	tokenPID, err := task.Args.GetNumberArg("token-pid")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the \"token-pid\" argument %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	user, err := task.Args.GetStringArg("username")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'username' argument %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	pass, err := task.Args.GetStringArg("password")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'password' argument %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	job := jobs.Command{
		Command: task.Task.CommandName,
	}

	var disp string
	switch strings.ToLower(task.Task.ParameterGroupName) {
	case "default":
		disp = fmt.Sprintf("%s", method)
		job.Args = append(job.Args, method)
		if args != "" {
			job.Args = append(job.Args, strings.Split(args, " ")...)
			disp += fmt.Sprintf(" %s", args)
		}
	case "make token":
		job.Args = append(job.Args, "make", user, pass)
		disp += fmt.Sprintf("make Username: %s, Password: %s", user, pass)
	case "steal token":
		job.Args = append(job.Args, "steal", fmt.Sprintf("%d", int(pid)))
		disp += fmt.Sprintf("steal %d", int(pid))
	case "token privs":
		job.Args = append(job.Args, "privs", fmt.Sprintf("%d", int(tokenPID)))
		disp += fmt.Sprintf("privs %d", int(tokenPID))
	default:
		err = fmt.Errorf("%s: unknown parameter group %s", pkg, task.Task.ParameterGroupName)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.MODULE)
	if err != nil {
		resp.Error = fmt.Sprintf("%s: %s", pkg, err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)

	resp.DisplayParams = &disp
	resp.Success = true

	return
}
