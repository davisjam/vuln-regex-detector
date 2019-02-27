FROM ubuntu:16.04

RUN apt-get update && apt-get install -y \
    sudo \
    wget

# Use Node 10.x (LTS); Xenial default (4.x) does not include npm
RUN wget -qO- https://deb.nodesource.com/setup_10.x | bash -

COPY . /app
WORKDIR /app
ENV VULN_REGEX_DETECTOR_ROOT /app

# configure calls apt-get install, so ensure it has fresh package list
RUN apt-get update && \
    JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF8 ./configure
