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

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/MythicMeta/MythicContainer/rabbitmq"
)

// socks creates and returns a Mythic Command structure registered with the Mythic server
func socks() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS, structs.SUPPORTED_OS_LINUX, structs.SUPPORTED_OS_MACOS, "freebsd", "openbsd", "solaris"},
	}

	action := structs.CommandParameter{
		Name:                                    "action",
		ModalDisplayName:                        "Action",
		CLIName:                                 "action",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
		Description:                             "Start or stop a SOCKS5 listener through this callback.",
		Choices:                                 []string{"start", "stop"},
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

	port := structs.CommandParameter{
		Name:                                    "port",
		ModalDisplayName:                        "Port",
		CLIName:                                 "port",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_NUMBER,
		Description:                             "Port number on Mythic server to open for SOCKS5 listener",
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
				UIModalPosition:       1,
				AdditionalInformation: nil,
			},
		},
	}

	params := []structs.CommandParameter{action, port}
	command := structs.Command{
		Name:                           "socks",
		NeedsAdminPermissions:          false,
		HelpString:                     "socks <action> <port>",
		Description:                    "Start or stop a SOCKS5 listener through this callback on the provided port.",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{"T1572"},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              params,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      socksCreateTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// socksCreateTask takes a Mythic Task and converts into a Merlin Job that is encoded into JSON and subsequently sent to the Merlin Agent
func socksCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/socks/socksCreateTask()"
	resp.TaskID = task.Task.ID

	action, err := task.Args.GetStringArg("action")
	if err != nil {
		resp.Error = fmt.Sprintf("%s: %s", pkg, err)
		resp.Success = false
		return
	}

	port, err := task.Args.GetNumberArg("port")
	if err != nil {
		resp.Error = fmt.Sprintf("%s: %s", pkg, err)
		resp.Success = false
		return
	}

	if action == "start" {
		m := mythicrpc.MythicRPCProxyStartMessage{
			TaskID:     task.Task.ID,
			LocalPort:  int(port),
			RemotePort: 0,
			RemoteIP:   "",
			PortType:   rabbitmq.CALLBACK_PORT_TYPE_SOCKS,
		}
		rpcResp, rpcErr := mythicrpc.SendMythicRPCProxyStart(m)
		if rpcErr != nil {
			resp.Error = fmt.Sprintf("%s: %s", pkg, rpcErr)
			resp.Success = false
			return
		}
		if !rpcResp.Success {
			resp.Error = fmt.Sprintf("%s: %s", pkg, rpcResp.Error)
			resp.Success = false
			return
		}
	}

	if action == "stop" {
		m := mythicrpc.MythicRPCProxyStopMessage{
			TaskID:   task.Task.ID,
			Port:     int(port),
			PortType: rabbitmq.CALLBACK_PORT_TYPE_SOCKS,
		}
		rpcResp, rpcErr := mythicrpc.SendMythicRPCProxyStop(m)
		if rpcErr != nil {
			resp.Error = fmt.Sprintf("%s: %s", pkg, rpcErr)
			resp.Success = false
			return
		}
		if !rpcResp.Success {
			resp.Error = fmt.Sprintf("%s: %s", pkg, rpcResp.Error)
			resp.Success = false
			return
		}
	}

	disp := fmt.Sprintf("%s SOCKS5 proxy on %d", action, int(port))
	resp.DisplayParams = &disp
	resp.Success = true
	return
}
