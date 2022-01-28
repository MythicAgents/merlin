
from merlin import *
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class ExecuteShellcodeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                display_name="Shellcode File",
                description="The binary file that contains the shellcode",
                type=ParameterType.File,
                parameter_group_info=[ParameterGroupInfo(
                    group_name="New File",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="filename",
                cli_name="filename",
                display_name="Shellcode File",
                description="The binary file that contains the shellcode",
                type=ParameterType.ChooseOne,
                dynamic_query_function=get_file_list,
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="method",
                cli_name="method",
                display_name="Process Injection Method",
                type=ParameterType.ChooseOne,
                choices=["self", "remote", "RtlCreateUserThread", "userapc"],
                description="The shellcode injection method to use",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=1,
                        required=True,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=1,
                        required=True,
                    ),
                ],
            ),
            CommandParameter(
                name="pid",
                cli_name="pid",
                display_name="Target PID",
                type=ParameterType.Number,
                description="The Process ID (PID) to inject the shellcode into. Not used with the 'self' method",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=2,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=2,
                        required=False,
                    ),
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)


class ExecuteShellcodeCommand(CommandBase):
    cmd = "execute-shellcode"
    needs_admin = False
    help_cmd = "execute-shellcode"
    description = "Execute the provided shellcode using the selected method. No output is captured or returned" \
                  "Change the Parameter Group to \"Default\" to use a file that was previously registered with " \
                  "Mythic and \"New File\" to register and use a new file from your host OS.\n"
    version = 1
    author = "@Ne0nd0g"
    argument_class = ExecuteShellcodeArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        shellcode_name, shellcode_uuid, contents = await get_file_contents(task)

        task.display_params = f'Shellcode: {shellcode_name} ' \
                              f'Method: {task.args.get_arg("method")} ' \
                              f'PID: {task.args.get_arg("pid")}'

        # Merlin jobs.Command message type
        command = {
            "method": task.args.get_arg("method").lower(),
            "bytes": contents,
        }

        if task.args.get_arg("pid"):
            command["pid"] = task.args.get_arg("pid")

        task.args.add_arg("type", MerlinJob.SHELLCODE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("file")
        task.args.remove_arg("filename")
        task.args.remove_arg("method")
        task.args.remove_arg("pid")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass



