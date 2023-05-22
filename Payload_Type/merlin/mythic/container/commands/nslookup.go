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

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// nslookup creates and return a Mythic Command structure that is registered with the Mythic server
func nslookup() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS, structs.SUPPORTED_OS_LINUX, structs.SUPPORTED_OS_MACOS, "Debian"},
	}

	host := structs.CommandParameter{
		Name:                                    "host",
		ModalDisplayName:                        "Hostname",
		CLIName:                                 "host",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "A space seperated list of hostnames or IP addresses to lookup and resolve",
		Choices:                                 nil,
		DefaultValue:                            "google.com",
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

	params := []structs.CommandParameter{host}
	command := structs.Command{
		Name:                           "nslookup",
		NeedsAdminPermissions:          false,
		HelpString:                     "nslookup <hostname1> <hostname2>...",
		Description:                    "Use Golang native commands to lookup and resolve a hostname or IP address",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              params,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      nslookupCreateTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// nslookupCreateTask takes a Mythic Task and converts into a Merlin Job that is encoded into JSON and subsequently sent to the Merlin Agent
func nslookupCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/nslookupg/nslookupCreateTask()"
	resp.TaskID = task.Task.ID

	hosts, err := task.Args.GetStringArg("host")
	if err != nil {
		resp.Error = fmt.Sprintf("%s: %s", pkg, err)
		resp.Success = false
		return
	}

	job := jobs.Command{
		Command: task.Task.CommandName,
		Args:    strings.Split(hosts, " "),
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.NATIVE)
	if err != nil {
		resp.Error = fmt.Sprintf("%s: %s", pkg, err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)

	disp := fmt.Sprintf("%s %s", hosts)
	resp.DisplayParams = &disp
	resp.Success = true

	return
}
