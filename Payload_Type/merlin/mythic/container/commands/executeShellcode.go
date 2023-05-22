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
	"encoding/base64"
	"encoding/json"
	"github.com/Ne0nd0g/merlin/pkg/jobs"

	// Mythic
	"fmt"
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"strings"
)

// executeShellcode returns a Mythic Command structure that is registered with the Mythic server
func executeShellcode() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS},
	}

	filename := structs.CommandParameter{
		Name:                                    "filename",
		ModalDisplayName:                        "Shellcode File",
		CLIName:                                 "shellcode",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
		Description:                             "The binary file that contains the shellcode",
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
		ModalDisplayName:                        "Shellcode File",
		CLIName:                                 "file",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_FILE,
		Description:                             "The binary file that contains the shellcode",
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

	method := structs.CommandParameter{
		Name:                                    "method",
		ModalDisplayName:                        "Process Injection Method",
		CLIName:                                 "method",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
		Description:                             "The shellcode injection method to use",
		Choices:                                 []string{"self", "remote", "RtlCreateUserThread", "userapc"},
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
			{
				ParameterIsRequired:   true,
				GroupName:             "New File",
				UIModalPosition:       1,
				AdditionalInformation: nil,
			},
		},
	}

	pid := structs.CommandParameter{
		Name:                                    "pid",
		ModalDisplayName:                        "Target Process ID",
		CLIName:                                 "pid",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_NUMBER,
		Description:                             "The Process ID (PID) to inject the shellcode into. Not used with the 'self' method",
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

	command := structs.Command{
		Name:                  "execute-shellcode",
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
		CommandParameters:              []structs.CommandParameter{file, filename, method, pid},
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      executeShellcodeCreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

func executeShellcodeCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/executeShellcode/executeShellcodeCreateTask()"
	resp.TaskID = task.Task.ID

	// Get the file as a byte array, its name, and any errors
	data, filename, err := GetFile(task)
	if err != nil {
		resp.Error = fmt.Sprintf("%s: %s", pkg, err)
		resp.Success = false
		return
	}

	// method
	var method string
	method, err = task.Args.GetStringArg("method")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"method\" command argument: %s", err)
		resp.Success = false
		return
	}

	// Process ID
	var pid float64
	pid, err = task.Args.GetNumberArg("pid")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"pid\" command argument: %s", err)
		resp.Success = false
		return
	}

	//  Merlin Job
	// Command: createprocess
	// Arguments:
	// 1. File contents as Base64 string
	// 2. SpawnTo executable file path on host where the Agent is running
	// 3. SpawnTo arguments

	job := jobs.Shellcode{
		Method: strings.ToLower(method),
		Bytes:  base64.StdEncoding.EncodeToString(data),
		PID:    uint32(pid),
	}

	jobBytes, err := json.Marshal(job)
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error JSON marshalling the Merlin jobs.Shellcode structure: %s", err)
		resp.Success = false
		return
	}

	mythicJob := Job{
		Type:    jobs.SHELLCODE,
		Payload: string(jobBytes),
	}
	mythicJobBytes, err := json.Marshal(mythicJob)
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error JSON marshalling the Job structure: %s", err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(string(mythicJobBytes))

	disp := fmt.Sprintf("Filename: %s, Method: %s, PID: %d", filename, method, int(pid))
	resp.DisplayParams = &disp
	resp.Success = true
	return
}
