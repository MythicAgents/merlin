
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class JA3Arguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="ja3string",
                cli_name="ja3string",
                display_name="JA3 STRING",
                type=ParameterType.String,
                description="The JA3 \"string\" that the client should use",
                value="",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=0,
                    required=True,
                )],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("ja3string", self.command_line)


class JA3Command(CommandBase):
    cmd = "ja3"
    needs_admin = False
    help_cmd = "ja3 <ja3 string>"
    description = "Instruct the agent to use a client derived from the input JA3 string to communicate with the " \
                  "server.\r\nWARNING: Make sure the server can support the client configuration"
    version = 1
    author = "@Ne0nd0g"
    argument_class = JA3Arguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{task.args.get_arg("ja3string")}'

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

        task.args.add_arg("type", MerlinJob.CONTROL, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("ja3string")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
