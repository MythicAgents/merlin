
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class NSLookupArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                cli_name="host",
                display_name="Hostname/IP",
                type=ParameterType.String,
                description="A space seperated list of hostnames or IP addresses to lookup and resolve",
                default_value="google.com",
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
                self.add_arg("host", self.command_line)


class NSLookupCommand(CommandBase):
    cmd = "nslookup"
    needs_admin = False
    help_cmd = "nslookup"
    description = "Use Golang native commands to lookup and resolve a hostname or IP address"
    version = 1
    author = "@Ne0nd0g"
    argument_class = NSLookupArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": task.args.get_arg("host").split(),
        }

        task.args.remove_arg("host")
        task.args.add_arg("type", MerlinJob.NATIVE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
