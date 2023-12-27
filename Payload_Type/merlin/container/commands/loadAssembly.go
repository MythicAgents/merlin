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

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message/jobs"
)

func loadAssembly() structs.Command {
	filename := structs.CommandParameter{
		Name:                                    "filename",
		ModalDisplayName:                        ".NET Assembly File",
		CLIName:                                 "filename",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
		Description:                             "The .NET assembly to load into the default AppDomain",
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
		ModalDisplayName:                        ".NET Assembly File",
		CLIName:                                 "file",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_FILE,
		Description:                             "The .NET assembly to load into the default AppDomain",
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
	parameters := []structs.CommandParameter{filename, file}
	command := structs.Command{
		Name:                  "load-assembly",
		NeedsAdminPermissions: false,
		HelpString: "Load a .NET assembly into the Agent's process that can be executed multiple " +
			"times without having to transfer the assembly over the network each time. Change the Parameter Group to " +
			"\\\"Default\\\" to use a file that was previously registered with Mythic and \\\"New File\\\" to register " +
			"and use a new file from your host OS.",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            nil,
		ScriptOnlyCommand:              false,
		CommandAttributes:              structs.CommandAttribute{SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS}},
		CommandParameters:              parameters,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      createLoadAssemblyTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}
	return command
}

func createLoadAssemblyTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/loadAssembly/loadAssemblyCreateTask()"
	resp.TaskID = task.Task.ID

	// Get the file as a byte array, its name, and any errors
	data, filename, err := GetFile(task)
	if err != nil {
		resp.Error = fmt.Sprintf("%s: %s", pkg, err)
		resp.Success = false
		return
	}

	job := jobs.Command{
		Command: "clr",
		Args:    []string{"load-assembly", base64.StdEncoding.EncodeToString(data), filename},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.MODULE)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/loadAssembly/createLoadAssemblyTask(): %s", err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)

	resp.DisplayParams = &filename
	resp.Success = true

	return
}
