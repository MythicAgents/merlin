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
	"encoding/base64"
	"fmt"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"

	// Merlin
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
				UIModalPosition:       2,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   false,
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
		TaskFunctionCreateTasking:      createProcessCreateTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// createProcessCreateTask takes a Mythic Task and converts into a Merlin Job that that is encoded into JSON and subsequently sent to the Merlin Agent
func createProcessCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/createProcess/createProcessCreateTask()"
	resp.TaskID = task.Task.ID

	// Get the file as a byte array, its name, and any errors
	data, filename, err := GetFile(task)
	if err != nil {
		err = fmt.Errorf("%s: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// Get SpawnTo command parameter
	spawnto, err := task.Args.GetStringArg("spawnto")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'spawnto' argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// Get SpawnTo Arguments command parameter
	args, err := task.Args.GetStringArg("args")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'args' argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	//  Merlin Job
	// Command: createprocess
	// Arguments:
	// 1. File contents as Base64 string
	// 2. SpawnTo executable file path on host where the Agent is running
	// 3. SpawnTo arguments

	job := jobs.Command{
		Command: "createprocess",
		Args:    []string{base64.StdEncoding.EncodeToString(data), spawnto, args},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.MODULE)
	if err != nil {
		err = fmt.Errorf("%s: there was an error converting the Merlin Job to a Mythic Task: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	task.Args.SetManualArgs(mythicJob)

	disp := fmt.Sprintf("Filename: %s, SpawnTo: %s, SpawnTo Arguments: %s", filename, spawnto, args)
	resp.DisplayParams = &disp

	resp.Success = true

	return
}
