from PayloadBuilder import *
import asyncio
import os
from distutils.dir_util import copy_tree
import tempfile
import time


# define your payload type class here, it must extend the PayloadType class though
class Merlin(PayloadType):
    name = "merlin"  # name that would show up in the UI
    file_extension = "exe"  # default file extension to use when creating payloads
    author = "Russel Van Tuyl - @Ne0nd0g"  # author of the payload type
    supported_os = [SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS]  # supported OS and architecture combos
    wrapper = False  # does this payload type act as a wrapper for another payloads inside of it?
    wrapped_payloads = []  # if so, which payload types
    note = """A port of Merlin from https://www.github.com/Ne0nd0g/merlin to Mythic"""
    supports_dynamic_loading = False  # setting this to True allows users to only select a subset of commands when generating a payload
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
            choices=["amd64", "386", "arm", "mips", "ketchup"],
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
    c2_profiles = ["HTTP"]

    # after your class has been instantiated by the mythic_service in this docker container and all required build parameters have values
    # then this function is called to actually build the payload
    async def build(self) -> BuildResponse:
        # this function gets called to create an instance of your payload
        resp = BuildResponse(status=BuildStatus.Error)
        output = ""
        command = ""

        # TODO Remove after finished troubleshooting error
        debug = True
        goCMD = ""
        c2Params = self.c2info[0].get_parameters_dict()

        # Merlin specific build code
        try:
            agent_build_path = tempfile.TemporaryDirectory(suffix=self.uuid).name
            merlinPath = "/go/src/github.com/Ne0nd0g/merlin-mythic-agent/"
            outputFile = "merlin"

            # shutil to copy payload files over
            copy_tree(self.agent_code_path, merlinPath)

            command = "cd " + merlinPath + ";"

            # Fix GOPATH 
            command += "export GOPATH=/go/src;"
            command += "export GOOS=" + self.get_parameter("os").lower() + ";"
            command += "export GOARCH=" + self.get_parameter("arch").lower() + ";"

            goCMD += "go build -o " + outputFile
            goCMD += """ -ldflags '-s -w"""
            if self.get_parameter("os").lower() == "windows":
                goCMD += " -H=windowsgui"
            # payloadID
            goCMD += " -X \"main.payloadID=" + f'{self.uuid}\"'
            # URL
            goCMD += f' -X \"main.url={c2Params["callback_host"]}:{c2Params["callback_port"]}/{c2Params["post_uri"]}\"'
            # Pre-Shared Key (PSK)
            goCMD += f' -X \"main.psk={c2Params["AESPSK"]}\"'
            # HTTP User-Agent
            goCMD += f' -X \"main.useragent={c2Params["USER_AGENT"]}\"'
            # Sleep
            goCMD += f' -X \"main.sleep={c2Params["callback_interval"]}s\"'
            # Skew
            skew = int(c2Params["callback_interval"]) * 1000
            goCMD += f' -X \"main.skew={skew}\"'
            # Kill Date
            killdate = str(int(time.mktime(time.strptime(c2Params["killdate"], "%Y-%m-%d"))))
            goCMD += f' -X \"main.killdate={killdate}\"'
            # Max Retry
            goCMD += f' -X \"main.maxretry={self.get_parameter("maxretry")}\"'
            # Padding
            goCMD += f' -X \"main.padding={self.get_parameter("padding")}\"'
            # Verbose
            goCMD += f' -X \"main.verbose={self.get_parameter("verbose")}\"'
            # Debug
            goCMD += f' -X \"main.debug={self.get_parameter("debug")}\"'
            # Proxy
            if c2Params["proxy_host"]:
                goCMD += f' -X \"main.proxy={c2Params["proxy_host"]}:{c2Params["proxy_port"]}\"'
            # HTTP Host Header
            if c2Params["domain_front"]:
                goCMD += f' -X \"main.host={c2Params["domain_front"]}\"'
            # JA3 String
            if self.get_parameter("ja3"):
                goCMD += f' -X \"main.ja3={self.get_parameter("ja3")}\"'

            # Everything else
            goCMD += " -buildid=\' main.go"

            # Build the agent
            command += goCMD

            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()
            if stdout:
                output += f"[STDOUT]\n{stdout.decode()}"
            if stderr:
                output += f"[STDERR]\n{stderr.decode()}"
            if debug:
                output += f"\r\n[DEBUG]\r\ncommand: {command}\r\ngoCMD: {goCMD}, "
            # Return compiled agent
            if os.path.exists(merlinPath + "/" + outputFile):
                resp.payload = open(merlinPath + "/" + outputFile, "rb").read()
                resp.message = "\r\nThe Merlin agent was successfully built"
                resp.message += f'\r\nGo build command: {goCMD}'
                resp.status = BuildStatus.Success
            else:
                # something went wrong, return our errors
                resp.message = output
        except Exception as e:
            resp.message = "[ERROR]" + str(e)

        return resp
