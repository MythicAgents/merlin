
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class RetryArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "maxretry": CommandParameter(
                name="maxretry",
                type=ParameterType.String,
                description="The maximum amount of times the Agent can fail to check in before it quits running",
                value="7",
                required=True,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("maxretry", str.split(self.command_line)[0])


class RetryCommand(CommandBase):
    cmd = "maxretry"
    needs_admin = False
    help_cmd = "maxretry"
    description = "The maximum amount of time the Agent can fail to check in before it quits running"
    version = 1
    author = "@Ne0nd0g"
    argument_class = RetryArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{task.args.get_arg("maxretry")}'

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": [task.args.get_arg("maxretry")],
        }

        task.args.add_arg("type", MerlinJob.CONTROL, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("maxretry")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
