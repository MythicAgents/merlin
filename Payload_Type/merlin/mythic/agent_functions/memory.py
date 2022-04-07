
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class MemoryArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="method",
                cli_name="method",
                display_name="Method",
                type=ParameterType.ChooseOne,
                choices=['patch', 'read', 'write'],
                default_value='patch',
                description="The method of interaction with the agent's virtual memory",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="module",
                cli_name="module",
                display_name="Module",
                type=ParameterType.String,
                description="The module (e.g., ntdll.dll) that contains the function you want to interact with",
                default_value="ntdll.dll",
                value="ntdll.dll",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=1,
                        required=True,
                    ),
                    ParameterGroupInfo(
                        group_name="Patch",
                        ui_position=1,
                        required=True,
                    ),
                    ParameterGroupInfo(
                        group_name="Read",
                        ui_position=1,
                        required=True,
                    ),
                    ParameterGroupInfo(
                        group_name="Write",
                        ui_position=1,
                        required=True,
                    ),
                ],
            ),
            CommandParameter(
                name="proc",
                cli_name="proc",
                display_name="Procedure",
                type=ParameterType.String,
                description="The procedure, or function, name (e.g., EtwEventWrite) that you want to interact with",
                default_value="EtwEventWrite",
                value="EtwEventWrite",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=2,
                        required=True,
                    ),
                    ParameterGroupInfo(
                        group_name="Patch",
                        ui_position=2,
                        required=True,
                    ),
                    ParameterGroupInfo(
                        group_name="Read",
                        ui_position=2,
                        required=True,
                    ),
                    ParameterGroupInfo(
                        group_name="Write",
                        ui_position=2,
                        required=True,
                    ),
                ],
            ),
            CommandParameter(
                name="bytes",
                cli_name="bytes",
                display_name="Bytes",
                type=ParameterType.String,
                description="The bytes, as a hex string, that you want to be written to memory",
                default_value="9090C3",
                value="9090C3",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=3,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="Patch",
                        ui_position=3,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="Write",
                        ui_position=3,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="length",
                cli_name="length",
                display_name="Length",
                type=ParameterType.Number,
                description="The number of bytes to read from the target procedure/function",
                default_value=6,
                value=6,
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=4,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="Read",
                        ui_position=4,
                        required=False,
                    ),
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                pass


class MemoryCommand(CommandBase):
    cmd = "memory"
    needs_admin = False
    help_cmd = "memory"
    description = "Read/Write the agent's virtual memory for the provided module and function\n" \
                  "\t - Use the \"Patch\" parameter group to read and then overwrite the target function's memory\n" \
                  "\t - Use the \"Read\" parameter group to read target function's memory\n" \
                  "\t - Use the \"Write\" parameter group to overwrite target function's memory with provided bytes\n"
    version = 1
    author = "@Ne0nd0g"
    argument_class = MemoryArguments
    attackmapping = ["T1562.001"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Parameter Group:{task.args.get_parameter_group_name()}')

        # Arguments
        # 0 - Method
        # 1 - Module
        # 2 - Procedure/Function
        # 3 - Bytes or Length (both as string)

        if task.args.get_parameter_group_name() == "Default":
            if task.args.get_arg("method").lower() == "read":
                args = [
                    task.args.get_arg("method"),
                    task.args.get_arg("module"),
                    task.args.get_arg("proc"),
                    str(task.args.get_arg("length")),
                ]
            else:
                args = [
                    task.args.get_arg("method").lower(),
                    task.args.get_arg("module"),
                    task.args.get_arg("proc"),
                    task.args.get_arg("bytes"),
                ]
        else:
            if task.args.get_arg("method").lower() == "read":
                args = [
                    task.args.get_parameter_group_name().lower(),
                    task.args.get_arg("module"),
                    task.args.get_arg("proc"),
                    str(task.args.get_arg("length")),
                ]
            else:
                args = [
                    task.args.get_parameter_group_name().lower(),
                    task.args.get_arg("module"),
                    task.args.get_arg("proc"),
                    task.args.get_arg("bytes"),
                ]

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": args,
        }

        display = ""
        for arg in args:
            display += f'{arg} '
        task.display_params = f'{display}'

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("method")
        task.args.remove_arg("module")
        task.args.remove_arg("proc")
        task.args.remove_arg("bytes")
        task.args.remove_arg("length")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
