
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class ENVArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "method": CommandParameter(
                name="method",
                type=ParameterType.ChooseOne,
                description="The desired environment interaction method",
                choices=["get", "set", "showall", "unset"],
                ui_position=0,
                required=True,
            ),
            "arguments": CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="Arguments for the env method",
                ui_position=1,
                required=False,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = str.split(self.command_line)
                if len(args) > 0:
                    self.add_arg("method", args[0])
                if len(args) > 1:
                    self.add_arg("arguments", " ".join(args[1:]))


class ENVCommand(CommandBase):
    cmd = "env"
    needs_admin = False
    help_cmd = "env"
    description = "Get, list, or set environment variables"
    version = 1
    author = "@Ne0nd0g"
    argument_class = ENVArguments
    attackmapping = []
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{task.args.get_arg("method")}'
        if task.args.get_arg("arguments") is not None:
            task.display_params += f' {task.args.get_arg("arguments")}'

        command = {
            "command": self.cmd,
            "args": [task.args.get_arg("method")],
        }

        if task.args.get_arg("arguments") is not None:
            for arg in task.args.get_arg("arguments").split():
                command["args"].append(arg)

        task.args.add_arg("type", MerlinJob.NATIVE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("method")
        task.args.remove_arg("arguments")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
