FROM itsafeaturemythic/mythic_base_image:0.0.1

WORKDIR /Mythic

# Copy in merlin/Payload_Type/merlin (location where this Docker file is) into the Docker image at /Mythic
COPY [".", "."]

# Download all the Go modules ahead of time, before compiling
RUN go mod download

# Build the Merlin container and save in the /usr/local/bin directory because it is in the PATH environment variable
# Do not save it in the Mythic directory because it is temporary while building and will be lost
RUN go build -o /usr/local/bin/MerlinContainer

CMD /usr/local/bin/MerlinContainer