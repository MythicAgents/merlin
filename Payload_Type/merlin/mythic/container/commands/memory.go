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

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// memory creates and return a Mythic Command structure that is registered with the Mythic server
func memory() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS},
	}

	method := structs.CommandParameter{
		Name:                                    "method",
		ModalDisplayName:                        "Method",
		CLIName:                                 "method",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
		Description:                             "The method of interaction with the agent's virtual memory",
		Choices:                                 []string{"patch", "read", "write"},
		DefaultValue:                            "patch",
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

	module := structs.CommandParameter{
		Name:                                    "module",
		ModalDisplayName:                        "Module",
		CLIName:                                 "module",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The module (e.g., ntdll.dll) that contains the function you want to interact with",
		Choices:                                 nil,
		DefaultValue:                            "ntdll.dll",
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
			{
				ParameterIsRequired:   true,
				GroupName:             "Patch",
				UIModalPosition:       1,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   true,
				GroupName:             "Read",
				UIModalPosition:       1,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   true,
				GroupName:             "Write",
				UIModalPosition:       1,
				AdditionalInformation: nil,
			},
		},
	}

	proc := structs.CommandParameter{
		Name:                                    "proc",
		ModalDisplayName:                        "Procedure",
		CLIName:                                 "proc",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The procedure, or function, name (e.g., EtwEventWrite) that you want to interact with",
		Choices:                                 nil,
		DefaultValue:                            "EtwEventWrite",
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
				UIModalPosition:       2,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   true,
				GroupName:             "Patch",
				UIModalPosition:       2,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   true,
				GroupName:             "Read",
				UIModalPosition:       2,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   true,
				GroupName:             "Write",
				UIModalPosition:       2,
				AdditionalInformation: nil,
			},
		},
	}

	bytes := structs.CommandParameter{
		Name:                                    "bytes",
		ModalDisplayName:                        "Bytes",
		CLIName:                                 "bytes",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The bytes, as a hex string, that you want to be written to memory",
		Choices:                                 nil,
		DefaultValue:                            "9090C3",
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
				UIModalPosition:       3,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   true,
				GroupName:             "Write",
				UIModalPosition:       3,
				AdditionalInformation: nil,
			},
		},
	}

	// Needed a parameter with a different name, so Mythic doesn't get confused on the exclusive set
	patchBytes := structs.CommandParameter{
		Name:                                    "patch-bytes",
		ModalDisplayName:                        "Bytes",
		CLIName:                                 "patch-bytes",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The bytes, as a hex string, that you want to be written to memory. Only used with the 'patch' method.",
		Choices:                                 nil,
		DefaultValue:                            "9090C3",
		SupportedAgents:                         nil,
		SupportedAgentBuildParameters:           nil,
		ChoicesAreAllCommands:                   false,
		ChoicesAreLoadedCommands:                false,
		FilterCommandChoicesByCommandAttributes: nil,
		DynamicQueryFunction:                    nil,
		ParameterGroupInformation: []structs.ParameterGroupInfo{
			{
				ParameterIsRequired:   true,
				GroupName:             "Patch",
				UIModalPosition:       3,
				AdditionalInformation: nil,
			},
		},
	}

	length := structs.CommandParameter{
		Name:                                    "length",
		ModalDisplayName:                        "Length",
		CLIName:                                 "length",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_NUMBER,
		Description:                             "The number of bytes to read from the target procedure/function",
		Choices:                                 nil,
		DefaultValue:                            6,
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
				UIModalPosition:       4,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   true,
				GroupName:             "Read",
				UIModalPosition:       4,
				AdditionalInformation: nil,
			},
		},
	}

	params := []structs.CommandParameter{method, module, proc, bytes, patchBytes, length}
	command := structs.Command{
		Name:                  "memory",
		NeedsAdminPermissions: false,
		HelpString:            "memory <method>",
		Description: "Read/Write the agent's virtual memory for the provided module and function." +
			" Use the \"Patch\" parameter group to read and then overwrite the target function's memory. " +
			"Use the \"Read\" parameter group to read target function's memory. " +
			"Use the \"Write\" parameter group to overwrite target function's memory with provided bytes.",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{"T1562.001"},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              params,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      memoryCreateTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// memoryCreateTask takes a Mythic Task and converts into a Merlin Job that is encoded into JSON and subsequently sent to the Merlin Agent
func memoryCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/memory/memoryCreateTask()"
	resp.TaskID = task.Task.ID

	method, err := task.Args.GetStringArg("method")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the \"method\" argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	module, err := task.Args.GetStringArg("module")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the \"module\" argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	proc, err := task.Args.GetStringArg("proc")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the \"proc\" argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	bytes, err := task.Args.GetStringArg("bytes")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the \"bytes\" argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	patchBytes, err := task.Args.GetStringArg("patch-bytes")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'patch-bytes' argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	length, err := task.Args.GetNumberArg("length")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the \"length\" argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	job := jobs.Command{
		Command: "memory",
	}

	var disp string
	switch strings.ToLower(task.Task.ParameterGroupName) {
	case "default":
		switch strings.ToLower(method) {
		case "read":
			job.Args = []string{method, module, proc, fmt.Sprintf("%d", int(length))}
			disp = fmt.Sprintf("%s %s:%s %d", method, module, proc, int(length))
		case "patch":
			job.Args = []string{method, module, proc, bytes}
			disp = fmt.Sprintf("%s %s:%s %s", method, module, proc, bytes)
		case "write":
			job.Args = []string{method, module, proc, bytes}
			disp = fmt.Sprintf("%s %s:%s %s", method, module, proc, bytes)
		default:
			err = fmt.Errorf("%s: unhandled parameter group name %s", pkg, task.Task.ParameterGroupName)
			resp.Error = err.Error()
			resp.Success = false
			logging.LogError(err, "returning with error")
			return
		}
	case "read":
		job.Args = []string{"read", module, proc, fmt.Sprintf("%d", int(length))}
		disp = fmt.Sprintf("%s %s:%s %d", strings.ToLower(task.Task.ParameterGroupName), module, proc, int(length))
	case "patch":
		job.Args = []string{"patch", module, proc, patchBytes}
		disp = fmt.Sprintf("%s %s:%s %s", strings.ToLower(task.Task.ParameterGroupName), module, proc, patchBytes)
	case "write":
		job.Args = []string{"write", module, proc, bytes}
		disp = fmt.Sprintf("%s %s:%s %s", strings.ToLower(task.Task.ParameterGroupName), module, proc, bytes)
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.MODULE)
	if err != nil {
		err = fmt.Errorf("%s: there was an error converting the Merlin job to a Mythic job: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	task.Args.SetManualArgs(mythicJob)

	resp.DisplayParams = &disp
	resp.Success = true

	return
}
