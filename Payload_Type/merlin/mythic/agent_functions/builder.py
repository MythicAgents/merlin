from mythic_payloadtype_container.PayloadBuilder import *
from mythic_payloadtype_container.MythicCommandBase import *
import asyncio
import os
import time

# Set to enable debug output to Mythic
debug = True


# define your payload type class here, it must extend the PayloadType class though
class Merlin(PayloadType):
    name = "merlin"  # name that would show up in the UI
    file_extension = "exe"  # default file extension to use when creating payloads
    author = "Russel Van Tuyl - @Ne0nd0g"  # author of the payload type
    supported_os = [SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS]  # supported OS and architecture combos
    wrapper = False  # does this payload type act as a wrapper for another payloads inside of it?
    wrapped_payloads = []  # if so, which payload types
    note = """A port of Merlin from https://www.github.com/Ne0nd0g/merlin to Mythic"""
    # setting this to True allows users to only select a subset of commands when generating a payload
    supports_dynamic_loading = False
    build_parameters = {
        #  these are all the build parameters that will be presented to the user when creating your payload
        "verbose": BuildParameter(
            name="verbose",
            description="Enable agent verbose output to STDOUT",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["false", "true"],
            required=False,
        ),
        "debug": BuildParameter(
            name="debug",
            description="Enable agent debug messages to STDOUT",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["false", "true"],
            required=False,
        ),
        "os": BuildParameter(
            name="os",
            description="What Operating System will the agent be running on.\r\nSelect DARWIN for macOS",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["windows", "darwin", "linux", "freebsd", "openbsd", "solaris"],
            required=False,
        ),
        "arch": BuildParameter(
            name="arch",
            description="What architecture will the agent be executed on?",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["amd64", "386", "arm", "mips"],
            required=False,
        ),
        "maxretry": BuildParameter(
          name="maxretry",
          description="How many times can the Agent fail to check in before it exits?",
          parameter_type=BuildParameterType.String,
          default_value="7",
          required=False,
        ),
        "padding": BuildParameter(
            name="padding",
            description="What is the maximum size of the random amount of data added to each message as padding?",
            parameter_type=BuildParameterType.String,
            default_value="4096",
            required=False,
        ),
        "ja3": BuildParameter(
            name="ja3",
            description="The JA3 string of the TLS configuration the agent should use",
            parameter_type=BuildParameterType.String,
            default_value="",
            required=False,
        )
    }
    #  the names of the c2 profiles that your agent supports
    c2_profiles = ["http"]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Error)
        go_cmd = ""
        c2_params = self.c2info[0].get_parameters_dict()

        # Merlin specific build code
        try:
            output_file = "merlin"

            # Fix GOPATH 
            command = "export GOPATH=/go/src;"
            command += "export GOOS=" + self.get_parameter("os").lower() + ";"
            command += "export GOARCH=" + self.get_parameter("arch").lower() + ";"

            go_cmd += "go build -o " + output_file
            go_cmd += """ -ldflags '-s -w"""
            if self.get_parameter("os").lower() == "windows" \
                    and (self.get_parameter("debug").lower() == "false"
                         and self.get_parameter("verbose").lower() == "false"):
                go_cmd += " -H=windowsgui"
            # payloadID
            go_cmd += " -X \"main.payloadID=" + f'{self.uuid}\"'
            # URL
            go_cmd += f' -X \"main.url={c2_params["callback_host"]}:{c2_params["callback_port"]}/{c2_params["post_uri"]}\"'
            # Pre-Shared Key (PSK)
            go_cmd += f' -X \"main.psk={c2_params["AESPSK"]["enc_key"]}\"'
            # HTTP Headers
            for header in c2_params["headers"]:
                if header["key"] == "User-Agent":
                    go_cmd += f' -X \"main.useragent={header["value"]}\"'
                elif header["key"] == "Host":
                    go_cmd += f' -X \"main.host={header["value"]}\"'
            # Sleep
            go_cmd += f' -X \"main.sleep={c2_params["callback_interval"]}s\"'
            # Skew
            skew = int(c2_params["callback_interval"]) * 1000
            go_cmd += f' -X \"main.skew={skew}\"'
            # Kill Date
            killdate = str(int(time.mktime(time.strptime(c2_params["killdate"], "%Y-%m-%d"))))
            go_cmd += f' -X \"main.killdate={killdate}\"'
            # Max Retry
            go_cmd += f' -X \"main.maxretry={self.get_parameter("maxretry")}\"'
            # Padding
            go_cmd += f' -X \"main.padding={self.get_parameter("padding")}\"'
            # Verbose
            go_cmd += f' -X \"main.verbose={self.get_parameter("verbose")}\"'
            # Debug
            go_cmd += f' -X \"main.debug={self.get_parameter("debug")}\"'
            # Proxy
            if c2_params["proxy_host"]:
                go_cmd += f' -X \"main.proxy={c2_params["proxy_host"]}:{c2_params["proxy_port"]}\"'
            # JA3 String
            if self.get_parameter("ja3"):
                go_cmd += f' -X \"main.ja3={self.get_parameter("ja3")}\"'

            # Everything else
            go_cmd += " -buildid=\' main.go"

            # Build the agent
            command += go_cmd

            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.agent_code_path,
            )

            stdout, stderr = await proc.communicate()

            if os.path.exists(str(self.agent_code_path.joinpath(output_file))):
                resp.payload = open(str(self.agent_code_path.joinpath(output_file)), "rb").read()
                resp.build_message += "\r\nThe Merlin agent was successfully built!"
                resp.build_stdout += f'\r\nGo build command: {go_cmd}\r\n'
                if stdout:
                    resp.build_stdout += f'{stdout.decode()}'
                if stderr:
                    resp.build_stderr += f'{stderr.decode()}'
                resp.status = BuildStatus.Success
            else:
                if stderr:
                    resp.build_stderr = f'{stderr.decode()}'
            if debug:
                resp.build_stdout += f"\r\n[DEBUG]\r\ncommand: {command}\r\ngo_cmd: {go_cmd}, "
        except Exception as e:
            resp.build_message = "[ERROR]" + str(e)
        return resp
