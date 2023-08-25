FROM mcr.microsoft.com/devcontainers/python:1-3.8-buster

# Install libpcap-dev
RUN apt-get update && apt-get install -y libpcap-dev
RUN apt-get update && apt-get install -y tcpdump && apt-get clean

