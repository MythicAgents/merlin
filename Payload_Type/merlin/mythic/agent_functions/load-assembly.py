
from merlin import *
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class LoadAssemblyArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                display_name=".NET Assembly File",
                description="The .NET assembly to load into the default AppDomain",
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
                display_name=".NET Assembly File",
                description="The .NET assembly to load into the default AppDomain",
                type=ParameterType.ChooseOne,
                dynamic_query_function=get_file_list,
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


class LoadAssemblyCommand(CommandBase):
    cmd = "load-assembly"
    needs_admin = False
    help_cmd = "load-assembly"
    description = "Load a .NET assembly into the Agent's process that can be executed multiple times without having " \
                  "to transfer the assembly over the network each time\n" \
                  "Change the Parameter Group to \"Default\" to use a file that was previously registered with " \
                  "Mythic and \"New File\" to register and use a new file from your host OS.\n"
    version = 1
    author = "@Ne0nd0g"
    argument_class = LoadAssemblyArguments
    attackmapping = []
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        assembly_name, assembly_uuid, contents = await get_file_contents(task)

        task.display_params = assembly_name

        # Arguments
        # 1. CLR command: load-assembly
        # 2. Base64 of .Net Assembly
        # 3. Assembly Name
        args = [
            self.cmd,
            contents,
            assembly_name,
        ]

    # Merlin jobs.Command message type
        command = {
            "command": "clr",
            "args": args,
        }

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("file")
        task.args.remove_arg("filename")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Filename: {len(args)}')
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
