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
	"strings"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"

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
		DefaultValue:                            nil,
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
	var shellcode []byte
	var filename string
	switch strings.ToLower(task.Task.ParameterGroupName) {
	case "default":
		v, err = task.Args.GetArg("filename")
		if err != nil {
			resp.Error = fmt.Sprintf("there was an error getting the \"filename\" command argument: %s", err)
			resp.Success = false
			return
		}
		filename = v.(string)
		shellcode, err = GetFileByName(filename)
		if err != nil {
			resp.Error = fmt.Sprintf("there was an error getting the file by its name \"%s\": %s", v.(string), err)
			resp.Success = false
			return
		}
	case "new file":
		// structs.COMMAND_PARAMETER_TYPE_FILE
		v, err = task.Args.GetArg("file")
		if err != nil {
			resp.Error = fmt.Sprintf("there was an error getting the \"file\" command argument: %s", err)
			resp.Success = false
			return
		}
		shellcode, err = GetFileContents(v.(string))
		if err != nil {
			resp.Error = fmt.Sprintf("there was an error getting the file by its id \"%s\": %s", v.(string), err)
			resp.Success = false
			return
		}
		filename, err = GetFileName(v.(string))
		if err != nil {
			resp.Error = fmt.Sprintf("there was an error getting the file name by its id \"%s\": %s", v.(string), err)
			resp.Success = false
			return
		}
	default:
		resp.Error = fmt.Sprintf("unknown parameter group: %s", task.Task.ParameterGroupName)
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
		Args:    []string{base64.StdEncoding.EncodeToString(shellcode), spawnto, args},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.MODULE)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/createProcess/createProcessCreateTask(): %s", err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)

	disp := fmt.Sprintf("Filename: %s, SpawnTo: %s, SpawnTo Arguments: %s", filename, spawnto, args)
	resp.DisplayParams = &disp

	resp.Success = true

	return
}
