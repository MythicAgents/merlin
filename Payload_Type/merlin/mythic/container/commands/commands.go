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

// Package commands holds all the Mythic command logic for issuing, receiving, and processing commands to Merlin
package commands

import (
	"fmt"
	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

type Command interface {
	Command() structs.Command
}

// Job structure
type Job struct {
	Type    int    `json:"type"`
	Payload string `json:"payload"`
}

// Commands returns a list of all the commands the Merlin agent payload supports
func Commands() (commands []structs.Command) {
	commands = append(commands, cd(), exit())
	return
}

// taskFunctionCreateTasking is a generic function to transform a Mythic Task into a format the Merlin Agent can understand
/*
	What Merlin gets from Mythic
	{
		"action":"get_tasking",
		"padding":"Sb",
		"tasks":[
			{
				"timestamp":1678920007,
				"command":"cd",
				"parameters":"/home/rastley/Downloads",
				"id":"28c242ef-97fe-4074-84de-4d5e40056f4f"
			}
		]
	}

	// The JSON object above is unmarshalled into this structure only used by the Mythic client in Merlin
	// through the convertToMerlinMessage() function
	// Merlin Agent ignores the Command field except for SOCKS messages
	type Task struct {
		ID      string  `json:"id"`
		Command string  `json:"command"`
		Params  string  `json:"parameters"`
		Time    float64 `json:"timestamp"`
	}

	The task params needs to be a JSON object that matches this Job structure
		The Job.Type directly relates to Merlin job types like CMD, CONTROL, or NATIVE
		The Job.Payload needs to be a JSON object that unmarshalled in to corresponding Merlin structure


	// The Task structure's Params field from above is JSON unmarshalled into this Job structure in the convertTasksToJobs() function
	// Job is a structure used only by the Mythic client in Merlin
	type Job struct {
		Type    int    `json:"type"`
		Payload string `json:"payload"`
	}

	// The Job structure's Payload field from above is JSON unmarshalled into this Command structure in the convertTasksToJobs() function
	// Command is the structure to send a task for the agent to execute
	type Command struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
*/
func taskFunctionCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	return structs.PTTaskCreateTaskingMessageResponse{
		TaskID:                 task.Task.ID,
		Success:                true,
		Error:                  "",
		CommandName:            nil,
		TaskStatus:             nil,
		DisplayParams:          nil,
		Stdout:                 nil,
		Stderr:                 nil,
		Completed:              nil,
		TokenID:                nil,
		CompletionFunctionName: nil,
		ParameterGroupName:     "",
	}
}

func taskFunctionParseArgDictionary(args *structs.PTTaskMessageArgsData, input map[string]interface{}) error {
	return nil
}

func taskFunctionParseArgString(args *structs.PTTaskMessageArgsData, input string) error {
	return nil
}

// GetFileList queries the Mythic server for files it knows about and returns a list of those Mythic file objects
// This function is used as a DynamicQuery to populate Mythic Command Parameter dropdown lists
func GetFileList(msg structs.PTRPCDynamicQueryFunctionMessage) (files []string) {
	search := mythicrpc.MythicRPCFileSearchMessage{
		TaskID:              0,
		CallbackID:          msg.Callback,
		Filename:            "",
		LimitByCallback:     false,
		MaxResults:          -1,
		Comment:             "",
		AgentFileID:         "",
		IsPayload:           false,
		IsDownloadFromAgent: false,
		IsScreenshot:        false,
	}
	resp, err := mythicrpc.SendMythicRPCFileSearch(search)
	if err != nil {
		fmt.Printf("Payload_Type/merlin/mythic/container/commands/GetFileList(): there was an error calling the SendMythicRPCFileSearch function: %s", err)
		return
	}

	if resp.Error != "" {
		fmt.Printf("Payload_Type/merlin/mythic/container/commands/GetFileList(): the SendMythicRPCFileSearch function returned a response message that contained an error: %s", resp.Error)
		return
	}

	for _, file := range resp.Files {
		files = append(files, file.Filename)
	}
	return
}

// GetFileByName queries the Mythic server for files that match the passed in name argument and returns the contents of the first match
func GetFileByName(name string) (contents []byte, err error) {
	search := mythicrpc.MythicRPCFileSearchMessage{
		TaskID:              0,
		CallbackID:          0,
		Filename:            name,
		LimitByCallback:     false,
		MaxResults:          -1,
		Comment:             "",
		AgentFileID:         "",
		IsPayload:           false,
		IsDownloadFromAgent: false,
		IsScreenshot:        false,
	}
	resp, err := mythicrpc.SendMythicRPCFileSearch(search)
	if err != nil {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileByName(): there was an error calling the SendMythicRPCFileSearch function: %s", err)
		return
	}

	if len(resp.Files) <= 0 {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileByName(): %d files were returned", len(resp.Files))
		return
	}

	for _, file := range resp.Files {
		if file.Filename == name {
			return GetFileContents(file.AgentFileId)
		}
	}
	return
}

// GetFileContents retrieves the file content as bytes for the provided fileID string
func GetFileContents(fileID string) (contents []byte, err error) {
	msg := mythicrpc.MythicRPCFileGetContentMessage{
		AgentFileID: fileID,
	}
	resp, err := mythicrpc.SendMythicRPCFileGetContent(msg)
	if err != nil {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileContents(): the SendMythicRPCFileGetContent function returned an error: %s", resp.Error)
		return
	}

	contents = resp.Content
	return
}
