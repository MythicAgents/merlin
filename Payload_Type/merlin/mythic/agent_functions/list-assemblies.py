
from CommandBase import *
from MythicResponseRPC import *
import json

# Set to enable debug output to Mythic
debug = False

class ListAssembliesArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        pass


class LoadAssemblyCommand(CommandBase):
    cmd = "list-assemblies"
    needs_admin = False
    help_cmd = "list-assemblies"
    description = "List the .NET assemblies that have been loaded in the default AppDomain in the Agent's process."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = ListAssembliesArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.MODULE
        task.args.add_arg("type", 16, ParameterType.Number)

        # Merlin jobs.Command message type
        command = {
            "command": "clr",
            "args": [self.cmd],
        }

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
