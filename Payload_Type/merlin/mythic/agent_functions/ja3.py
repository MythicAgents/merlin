from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicResponseRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class JA3Arguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "ja3string": CommandParameter(
                name="ja3string",
                type=ParameterType.String,
                description="The JA3 \"string\" that the client should use",
                value="",
                required=True,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("ja3string", str.split(self.command_line)[0])


class JA3Command(CommandBase):
    cmd = "ja3"
    needs_admin = False
    help_cmd = "ja3"
    description = "Instruct the agent to use a client derived from the input JA3 string to communicate with the " \
                  "server.\r\nWARNING: Make sure the server can support the client configuration"
    version = 1
    author = "@Ne0nd0g"
    argument_class = JA3Arguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.CONTROL
        task.args.add_arg("type", 11, ParameterType.Number)

        # Arguments
        args = []
        arguments = task.args.get_arg("ja3string")
        if arguments:
            args.append(arguments)

        # Merlin jobs.Command message type
        command = {
            "command": "ja3",
            "args": args,
        }

        task.display_params = f'{task.args.get_arg("ja3string")}'
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("ja3string")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
