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

// invokeAssembly returns a Mythic Command structure that is registered with the Mythic server that subsequently
// instructs the Merlin Agent to invoke (execute) a .NET assembly that was previously loaded into the Agent's process
// using the load-assembly command. Use the list-assemblies command to view loaded assemblies
func invokeAssembly() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS},
	}

	assembly := structs.CommandParameter{
		Name:                                    "assembly",
		ModalDisplayName:                        ".NET Assembly",
		CLIName:                                 "assembly",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "Name of the previously loaded assembly to execute",
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

	arguments := structs.CommandParameter{
		Name:                                    "arguments",
		ModalDisplayName:                        ".NET Assembly Arguments",
		CLIName:                                 "args",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "Arguments to invoke (execute) the assembly",
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

	command := structs.Command{
		Name:                           "invoke-assembly",
		NeedsAdminPermissions:          false,
		HelpString:                     "",
		Description:                    "Invoke (execute) a .NET assembly that was previously loaded into the Agent's process using the load-assembly command. Use the list-assemblies command to view loaded assemblies\"",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            nil,
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              []structs.CommandParameter{assembly, arguments},
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      invokeAssemblyCreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

func invokeAssemblyCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/invokeAssembly/invokeAssemblyCreateTask()"
	resp.TaskID = task.Task.ID

	assembly, err := task.Args.GetStringArg("assembly")
	if err != nil {
		err = fmt.Errorf("%s there was an error getting the \"assembly\" argument's value for the \"invoke-assembly\" command: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	job := jobs.Command{
		Command: "clr",
		Args:    []string{task.Task.CommandName, assembly},
	}

	args, err := task.Args.GetStringArg("arguments")
	if err != nil {
		err = fmt.Errorf("%s there was an error getting the \"arguments\" argument's value for the \"invoke-assembly\" command: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	if args != "" {
		job.Args = append(job.Args, strings.Split(args, " ")...)
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.MODULE)
	if err != nil {
		err = fmt.Errorf("%s: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	task.Args.SetManualArgs(mythicJob)
	disp := fmt.Sprintf("%s %s", assembly, args)
	resp.DisplayParams = &disp
	resp.Success = true

	return
}
