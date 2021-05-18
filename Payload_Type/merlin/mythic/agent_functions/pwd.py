from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class PWDArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        pass


class PWDCommand(CommandBase):
    cmd = "pwd"
    needs_admin = False
    help_cmd = "pwd"
    description = "Print the Agent's current working directory"
    version = 1
    author = "@Ne0nd0g"
    argument_class = PWDArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.NATIVE
        task.args.add_arg("type", 13, ParameterType.Number)

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
        }

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
