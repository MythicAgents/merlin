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
	"encoding/json"
	"fmt"
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// createProcess creates and return a Mythic Command structure that is registered with the Mythic server
// This command uses process hollowing to create a child process from the spawnto argument, allocate the provided
// shellcode into it, execute it, and use anonymous pipes to collect and return STDOUT/STDERR.
func createProcess() structs.Command {
	filename := structs.CommandParameter{
		Name:                                    "filename",
		ModalDisplayName:                        "",
		CLIName:                                 "shellcode",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
		Description:                             "The shellcode filename you want to execute in the spawnto process",
		Choices:                                 nil,
		DefaultValue:                            nil,
		SupportedAgents:                         nil,
		SupportedAgentBuildParameters:           nil,
		ChoicesAreAllCommands:                   false,
		ChoicesAreLoadedCommands:                false,
		FilterCommandChoicesByCommandAttributes: nil,
		DynamicQueryFunction:                    GetFileList,
		ParameterGroupInformation: []structs.ParameterGroupInfo{
			{
				ParameterIsRequired:   true,
				GroupName:             "Default",
				UIModalPosition:       0,
				AdditionalInformation: nil,
			},
		},
	}

	file := structs.CommandParameter{
		Name:                                    "file",
		ModalDisplayName:                        "file",
		CLIName:                                 "file",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_FILE,
		Description:                             "The shellcode file you want to execute in the spawnto process",
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
				GroupName:             "New File",
				UIModalPosition:       0,
				AdditionalInformation: nil,
			},
		},
	}

	spawnto := structs.CommandParameter{
		Name:                                    "spawnto",
		ModalDisplayName:                        "SpawnTo",
		CLIName:                                 "spawnto",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The child process that will be started to execute the shellcode in",
		Choices:                                 nil,
		DefaultValue:                            "C:\\Windows\\System32\\WerFault.exe",
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
				GroupName:             "New File",
				UIModalPosition:       1,
				AdditionalInformation: nil,
			},
		},
	}

	spawntoArgs := structs.CommandParameter{
		Name:                                    "args",
		ModalDisplayName:                        "SpawnTo Agruments",
		CLIName:                                 "args",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "arguments to create the spawnto process with, if any",
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
				UIModalPosition:       2,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   true,
				GroupName:             "New File",
				UIModalPosition:       2,
				AdditionalInformation: nil,
			},
		},
	}

	parameters := []structs.CommandParameter{filename, file, spawnto, spawntoArgs}
	command := structs.Command{
		Name:                           "create-process",
		NeedsAdminPermissions:          false,
		HelpString:                     "create-process <shellcode file name> <spawnto> <spawnto args>\ncreate-process -shellcode <shellcode filename> -spawnto <spawnto> -args <spawnto args>",
		Description:                    "Uses process hollowing to create a child process from the spawnto argument, allocate the provided shellcode into it, execute it, and use anonymous pipes to collect STDOUT/STDERR\nChange the Parameter Group to \"Default\" to use a shellcode file that was previously registered with Mythic and \"New File\" to register and use a new shellcode file from your host OS.",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{"T1055"},
		ScriptOnlyCommand:              false,
		CommandAttributes:              structs.CommandAttribute{SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS}},
		CommandParameters:              parameters,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      taskFunctionCreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// createProcessCreateTask task a Mythic Task and converts into a Merlin Job that that is encoded into JSON and subsequently sent to the Merlin Agent
func createProcessCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID

	// Get SpawnTo command parameter
	v, err := task.Args.GetArg("spawnto")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"spawnto\" command argument: %s", err)
		resp.Success = false
		return
	}
	spawnto := v.(string)

	// Get SpawnTo Arguments command parameter
	v, err = task.Args.GetArg("args")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"args\" command argument: %s", err)
		resp.Success = false
		return
	}
	args := v.(string)

	// Determine if a "filename" or "file" Mythic command argument was provided
	v, err = task.Args.GetArg("filename")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"filename\" command argument: %s", err)
		resp.Success = false
		return
	}
	filename := v.(string)

	var contents []byte
	// If a "filename" was provided, get it
	if filename != "" {
		contents, err = GetFileByName(filename)
	} else {

	}

	//  Merlin Job
	// Command: createprocess
	// Arguments:
	// 1. file contents
	// 2. SpawnTo executable file path on host where the Agent is running
	// 3. SpawnTo arguments

	job := jobs.Command{
		Command: task.Task.CommandName,
		Args:    []string{string(contents), spawnto, args},
	}

	jobBytes, err := json.Marshal(job)
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error JSON marshalling the Merlin jobs.Job structure: %s", err)
		resp.Success = false
		return
	}

	mythicJob := Job{
		Type:    jobs.MODULE,
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
