
from merlin import MerlinJob, get_file_list, get_file_contents
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json
import shlex

# Set to enable debug output to Mythic
debug = False


class MemfdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="The Linux executable file you want to run",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="New File",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="filename",
                cli_name="executable",
                display_name="Filename within Mythic",
                description="Previously registered file to execute",
                type=ParameterType.ChooseOne,
                dynamic_query_function=get_file_list,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        ui_position=0,
                        group_name="Default",
                    )
                ]
            ),
            CommandParameter(
                name="arguments",
                cli_name="args",
                type=ParameterType.String,
                description="Arguments to start the executable with",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=1,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=1,
                        required=False,
                    )
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                # This allows an operator to specify the name of a file that was previously registered with Mythic
                # in place of providing the actual file
                args = shlex.split(self.command_line)
                if len(args) > 0:
                    self.add_arg("executable-name", args[0], ParameterType.String)
                if len(args) > 1:
                    self.add_arg("arguments", " ".join(args[1:]), ParameterType.String)


class MemfdCommand(CommandBase):
    cmd = "memfd"
    needs_admin = False
    help_cmd = "memfd <executable name> <args>"
    description = "Load a Linux executable file into memory (RAM) as an anonymous file using the memfd_create API " \
                  "call, execute it, and returns the results.\n" \
                  "Change the Parameter Group to \"Default\" to use a file that was previously registered with Mythic " \
                  "and \"New File\" to register and use a new file from your host OS.\n"
    version = 1
    author = "@Ne0nd0g"
    argument_class = MemfdArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Linux]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        executable_name, _, contents = await get_file_contents(task)

        if task.args.get_arg("arguments") is not None:
            task.display_params = f'{executable_name} {task.args.get_arg("arguments")}'
        else:
            task.display_params = f'{executable_name}'

        # Arguments
        # 1. Base64 of Executable
        # 2+ Executable Arguments
        args = [
            contents,
        ]

        if task.args.get_arg("arguments") is not None:
            for arg in task.args.get_arg("arguments").split():
                args.append(arg)

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": args,
        }

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("file")
        task.args.remove_arg("filename")
        task.args.remove_arg("arguments")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
