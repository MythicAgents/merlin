
from mythic_payloadtype_container.PayloadBuilder import *
from mythic_payloadtype_container.MythicCommandBase import *
import asyncio
import os
import time
import secrets

# Set to enable debug output to Mythic
debug = False


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
        ),
        "garble": BuildParameter(
            name="garble",
            description="Use Garble to obfuscate the output Go executable. WARNING - This significantly slows the agent build time",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["false", "true"],
            default_value="false",
            required=False,
        ),
    }
    #  the names of the c2 profiles that your agent supports
    c2_profiles = ["http"]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Error)
        c2_params = self.c2info[0].get_parameters_dict()

        # Merlin specific build code
        try:
            output_file = "merlin"

            # Remove old binary if it exists
            if os.path.exists(str(self.agent_code_path.joinpath(output_file))):
                os.remove(str(self.agent_code_path.joinpath(output_file)))

            # Fix GOPATH 
            command = "export GOPATH=/go/src;"
            command += "export GOOS=" + self.get_parameter("os").lower() + ";"
            command += "export GOARCH=" + self.get_parameter("arch").lower() + ";"

            if self.get_parameter("garble").lower() == "true":
                # Can't garble or include in GOPRIVATE: go.dedis.ch/kyber,golang.org/x/sys
                # Can't use Garble because it doesn't handle ldflags for -X parameters
                # https://github.com/burrowers/garble/issues/323
                # Currently the only option is to open the file and replace the strings to prevent using ldflags
                command += "export GOPRIVATE=github.com,gopkg.in,golang.org/x/net,golang.org/x/text;"
                command += "export CGO_ENABLED=0;"
                go_cmd = f'garble -tiny -literals -seed {secrets.token_hex(32)} build -o {output_file} -ldflags \''

                # For the record, I'm not a fan of doing things this way. Temporary until Garble can handle ldflags
                merlin = open(str(self.agent_code_path.joinpath("main.go")), "rt")
                data = merlin.read()
                # payloadID
                data = data.replace('var payloadID = ""', f'var payloadID = "{self.uuid}"')
                # URL
                data = data.replace('var url = "https://127.0.0.1:443"', f'var url = "{c2_params["callback_host"]}:{c2_params["callback_port"]}/{c2_params["post_uri"]}"')
                # Pre-Shared Key (PSK)
                data = data.replace('var psk string', f'var psk = "{c2_params["AESPSK"]["enc_key"]}"')
                # HTTP Headers
                for header in c2_params["headers"]:
                    if header["key"] == "User-Agent":
                        data = data.replace('var useragent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"', f'var useragent = "{header["value"]}"')
                    elif header["key"] == "Host":
                        data = data.replace('var host string', f'var host = "{header["value"]}"')
                # Sleep
                data = data.replace('var sleep = "30s"', f'var sleep = "{c2_params["callback_interval"]}s"')
                # skew
                data = data.replace('var skew = "3000"', f'var skew = "{int(c2_params["callback_interval"]) * 1000}"')
                # Kill Date
                data = data.replace('var killdate = "0"', f'var killdate = "{str(int(time.mktime(time.strptime(c2_params["killdate"], "%Y-%m-%d"))))}"')
                # Max Retry
                data = data.replace('var maxretry = "7"', f'var maxretry = "{self.get_parameter("maxretry")}"')
                # Padding
                data = data.replace('var padding = "4096"', f'var padding = "{self.get_parameter("padding")}"')
                # Verbose
                data = data.replace('var verbose = "false"', f'var verbose = "{self.get_parameter("verbose")}"')
                # Debug
                data = data.replace('var debug = "false"', f'var debug = "{self.get_parameter("debug")}"')
                # Proxy
                if c2_params["proxy_host"]:
                    data = data.replace('var proxy string', f'var proxy = "{c2_params["proxy_host"]}:{c2_params["proxy_port"]}"')
                # JA3 String
                if self.get_parameter("ja3"):
                    data = data.replace('var ja3 string', f'var ja3 = "{self.get_parameter("ja3")}"')

                # Write to a new file to preserve the original source
                garbled = open(str(self.agent_code_path.joinpath("garbled.go")), "wt")
                garbled.write(data)
                garbled.close()
                merlin.close()
            else:
                go_cmd = f'go build -o {output_file} -ldflags \'-s -w '

            if self.get_parameter("os").lower() == "windows" \
                    and (self.get_parameter("debug").lower() == "false"
                         and self.get_parameter("verbose").lower() == "false"):
                go_cmd += "-H=windowsgui "
            # payloadID
            go_cmd += "-X \"main.payloadID=" + f'{self.uuid}\"'
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
            if self.get_parameter("garble").lower() == "true":
                go_cmd += " -buildid=\' garbled.go"
            else:
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
                # os.remove(str(self.agent_code_path.joinpath(output_file)))
                if stdout:
                    resp.build_stdout += f'STDOUT\n{stdout.decode()}'
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
