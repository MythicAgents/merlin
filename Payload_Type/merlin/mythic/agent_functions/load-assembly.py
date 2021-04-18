
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicResponseRPC import *
from mythic_payloadtype_container.MythicFileRPC import *
import json


# Set to enable debug output to Mythic
debug = False


class LoadAssemblyArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "assembly": CommandParameter(
                name="assembly",
                type=ParameterType.File,
                description="The .NET assembly to load into the default AppDomain",
                required=True,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)


class LoadAssemblyCommand(CommandBase):
    cmd = "load-assembly"
    needs_admin = False
    help_cmd = "load-assembly"
    description = "Load a .NET assembly into the Agent's process that can be executed multiple times without having " \
                  "to transfer the assembly over the network each time"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = LoadAssemblyArguments
    attackmapping = []
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.MODULE
        task.args.add_arg("type", 16, ParameterType.Number)

        # Arguments
        # 1. CLR command: load-assembly
        # 2. Base64 of .Net Assembly
        # 3. Assembly Name
        args = [self.cmd]

        if task.args.get_arg("assembly") is None:
            # the user supplied an assembly name instead of uploading one, see if we can find it
            resp = await MythicFileRPC(task).get_file_by_name(task.args.command_line)
            if resp.status == MythicStatus.Success:
                args.append(base64.b64encode(resp.contents).decode("utf-8"))
                args.append(resp.filename)
            else:
                raise ValueError(
                    "Failed to find file:  {}".format(task.args.command_line)
                )
        else:
            filename = json.loads(task.original_params)["assembly"]
            resp = await MythicFileRPC(task).register_file(
                file=task.args.get_arg("assembly"),
                saved_file_name=filename,
                delete_after_fetch=False,
            )
            if resp.status != MythicStatus.Success:
                raise ValueError(
                    "Failed to register file with Mythic: {}".format(resp.error_message)
                )
            args.append(base64.b64encode(task.args.get_arg("assembly")).decode("utf-8"))
            args.append(json.loads(task.original_params)["assembly"])

        # Merlin jobs.Command message type
        command = {
            "command": "clr",
            "args": args,
        }

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("assembly")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Filename: {len(args)}')
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        task.display_params = json.loads(task.original_params)["assembly"]
        return task

    async def process_response(self, response: AgentResponse):
        pass
