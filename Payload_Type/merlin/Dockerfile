FROM ne0nd0g/merlin-base:v1.5.0

# FROM itsafeaturemythic/mythic_go_base:1.0.4-rc08
# https://github.com/MythicMeta/Mythic_Docker_Templates/blob/master/mythic_go_base/Dockerfile

WORKDIR /Mythic

# Copy in merlin/Payload_Type/merlin (location where this Docker file is) into the Docker image at /Mythic
COPY [".", "."]

# Download all the Go modules ahead of time, before compiling
WORKDIR /Mythic/agent
RUN go mod download
WORKDIR /Mythic/container
RUN go mod download

# Build the Merlin container and save in the /usr/local/bin directory because it is in the PATH environment variable
# Do not save it in the Mythic directory because it is temporary while building and will be lost
RUN go build -o /usr/local/bin/MerlinContainer

CMD /usr/local/bin/MerlinContainer