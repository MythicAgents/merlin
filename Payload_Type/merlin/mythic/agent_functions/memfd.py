from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicResponseRPC import *

# Set to enable debug output to Mythic
debug = False


class MemfdArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "executable": CommandParameter(
                name="executable",
                type=ParameterType.File,
                description="The Linux executable (PE file) you want to run",
                ui_position=0,
                required=True,
            ),
            "arguments": CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="Arguments to start the executable with",
                ui_position=1,
                required=False,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("path", str.split(self.command_line)[0])


class MemfdCommand(CommandBase):
    cmd = "memfd"
    needs_admin = False
    help_cmd = "memfd"
    description = "Load a Linux executable file into memory (RAM) as an anonymous file using the memfd_create API " \
                  "call, execute it, and returns the results."
    version = 1
    author = "@Ne0nd0g"
    argument_class = MemfdArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Linux]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.MODULE
        task.args.add_arg("type", 16, ParameterType.Number)

        # Arguments
        # 1. Base64 of Executable
        # 2+ Executable Arguments
        args = [
            base64.b64encode(task.args.get_arg("executable")).decode("utf-8"),
        ]

        arguments = task.args.get_arg("arguments").split()
        if len(arguments) == 1:
            args.append(arguments[0])
        elif len(arguments) > 1:
            for arg in arguments:
                args.append(arg)

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": args,
        }

        task.display_params = f'{json.loads(task.original_params)["executable"]} {task.args.get_arg("arguments")}'
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("executable")
        task.args.remove_arg("args")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
