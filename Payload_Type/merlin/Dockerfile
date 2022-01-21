FROM merlin-base:latest

# Configure Mythic Packages
RUN pip install aio_pika requests mythic-payloadtype-container==0.1.0 dynaconf==3.1.4

WORKDIR /Mythic

ENTRYPOINT ["/Mythic/mythic/payload_service.sh"]