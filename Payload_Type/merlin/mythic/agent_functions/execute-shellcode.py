
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicResponseRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class ExecuteShellcodeArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "shellcode": CommandParameter(
                name="shellcode",
                type=ParameterType.File,
                description="The binary file that contains the shellcode",
                required=True,
            ),
            "method": CommandParameter(
                name="method",
                type=ParameterType.ChooseOne,
                choices=["self", "remote", "RtlCreateUserThread", "userapc"],
                description="The shellcode injection method to use",
                required=True
            ),
            "pid": CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="The Process ID (PID) to inject the shellcode into. Not used with the 'self' method",
                required=False
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)


class ExecuteShellcodeCommand(CommandBase):
    cmd = "execute-shellcode"
    needs_admin = False
    help_cmd = "execute-shellcode"
    description = "Execute the provided shellcode using the selected method. No output is captured or returned"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = ExecuteShellcodeArguments
    attackmapping = ["1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.SHELLCODE
        task.args.add_arg("type", 12, ParameterType.Number)

        # Merlin jobs.Command message type
        command = {
            "method": task.args.get_arg("method").lower(),
            "bytes": base64.b64encode(task.args.get_arg("shellcode")).decode("utf-8"),
        }

        if task.args.get_arg("pid"):
            command["pid"] = task.args.get_arg("pid")

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("method")
        task.args.remove_arg("shellcode")
        task.args.remove_arg("pid")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass



