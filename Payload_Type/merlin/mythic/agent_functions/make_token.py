
from merlin import *
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class MakeTokenArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="user",
                cli_name="user",
                display_name="Username",
                type=ParameterType.String,
                description="Domain and username to make a token for (e.g. ACME\\RASTLEY",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=1,
                        required=True,
                    ),
                ],
            ),
            CommandParameter(
                name="pass",
                cli_name="pass",
                display_name="Password",
                type=ParameterType.String,
                description="The account's password",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=2,
                        required=True,
                    ),
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = str.split(self.command_line)
                if len(args) > 0:
                    self.add_arg("user", args[0])
                if len(args) > 1:
                    self.add_arg("pass", args[1])


class MakeTokenCommand(CommandBase):
    cmd = "make_token"
    needs_admin = False
    help_cmd = "make_token <DOMAIN\\Username> <password>"
    description = "Create a new type-9 logon session and Windows access token for the provided credentials.\n" \
                  "The token is only used for NETWORK authentication, not local."
    version = 1
    author = "@Ne0nd0g"
    argument_class = MakeTokenArguments
    attackmapping = ["T1134.003"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        task.display_params = f'User: {task.args.get_arg("user")}, Password: {task.args.get_arg("pass")}'

        command = {
            "command": "token",
            "args": ["make", f'{task.args.get_arg("user")}', f'{task.args.get_arg("pass")}'],
        }

        task.args.remove_arg("user")
        task.args.remove_arg("pass")
        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'\n[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
