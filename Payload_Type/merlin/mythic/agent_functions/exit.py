
from CommandBase import *
import json


class ExitArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        pass


class ExitCommand(CommandBase):
    cmd = "exit"
    needs_admin = False
    help_cmd = "exit"
    description = "instruct the agent to quit running and exit"
    version = 1
    is_exit = True
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = ExitArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.Command message type
        command = {
            "command": "kill",
        }

        task.args.add_arg("type", 11, ParameterType.Number) # jobs.CONTROL
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        return task

    async def process_response(self, response: AgentResponse):
        pass