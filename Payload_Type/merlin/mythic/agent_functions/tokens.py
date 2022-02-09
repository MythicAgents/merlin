
from merlin import *
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class TokensArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="method",
                cli_name="method",
                display_name="Method",
                type=ParameterType.ChooseOne,
                description="The \"method\" to interact with Windows access tokens",
                choices=["make", "privs", "rev2self", "steal", "whoami"],
                default_value="whoami",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=0,
                        required=True,
                    ),
                ],
            ),
            CommandParameter(
                name="arguments",
                cli_name="args",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments that are specific to the selected token method",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=1,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="pid",
                cli_name="pid",
                display_name="Process ID",
                type=ParameterType.String,
                description="The process ID to interact with",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Steal Token",
                        ui_position=1,
                        required=True,
                    ),
                ],
            ),
            CommandParameter(
                name="token-pid",
                cli_name="token-pid",
                display_name="Process ID",
                type=ParameterType.String,
                description="The process ID to interact with",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Token Privs",
                        ui_position=1,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="user",
                cli_name="user",
                display_name="Username",
                type=ParameterType.String,
                description="Domain and username to make a token for (e.g. ACME\\RASTLEY",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Make Token",
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
                        group_name="Make Token",
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
                raise Exception(f'task_dictionary: {self.task_dictionary}')


class TokensCommand(CommandBase):
    cmd = "token"
    needs_admin = False
    help_cmd = "token -method <method> "
    description = "Interact with Windows access tokens.\n" \
                  "\t - Use the \"Make Token\" parameter group to create a new access token.\n" \
                  "\t - Use the \"Steal Token\" parameter group to steal an access token.\n" \
                  "\t - Use the \"Token Privs\" parameter group to view a token's privileges\n" \
                  "\t - The \"Default\" parameter group can be used to interact with ANY method."
    version = 1
    author = "@Ne0nd0g"
    argument_class = TokensArguments
    attackmapping = ["T1134"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        # Arguments
        args = []
        if task.args.get_parameter_group_name() == "Default":
            args = [task.args.get_arg("method")]
            if task.args.get_arg("arguments"):
                args.append(task.args.get_arg("arguments"))
                task.display_params = f'{task.args.get_arg("method")} {task.args.get_arg("arguments")}'
            else:
                task.display_params = f'{task.args.get_arg("method")}'
            task.args.remove_arg("method")
            task.args.remove_arg("arguments")
        elif task.args.get_parameter_group_name() == "Make Token":
            args = [
                "make",
                task.args.get_arg("user"),
                task.args.get_arg("pass"),
            ]
            task.display_params = f'make {task.args.get_arg("user")} {task.args.get_arg("pass")}'
            task.args.remove_arg("user")
            task.args.remove_arg("pass")
        elif task.args.get_parameter_group_name() == "Steal Token":
            args = [
                "steal",
                task.args.get_arg("pid"),
            ]
            task.display_params = f'steal {task.args.get_arg("pid")}'
            task.args.remove_arg("pid")
        elif task.args.get_parameter_group_name() == "Token Privs":
            args = ["privs"]
            if task.args.get_arg("token-pid") != "":
                args.append(task.args.get_arg("token-pid"))
            task.display_params = f'privs {task.args.get_arg("token-pid")}'
            task.args.remove_arg("token-pid")
        else:
            raise Exception(f'Unhandled token parameter group {task.args.get_parameter_group_name()}')

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": args,
        }

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'\n[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
