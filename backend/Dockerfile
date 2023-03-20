# See: https://levelup.gitconnected.com/debugging-go-inside-docker-using-visual-studio-code-and-remote-containers-5c3724fe87b9
# See for available variants: https://hub.docker.com/_/golang?tab=tags
ARG VARIANT=1.20.2-bullseye
FROM golang:${VARIANT}

COPY entrypoint.sh entrypoint-dev.sh /

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install libvpx-dev libogg-dev libvorbis-dev libopus-dev portaudio19-dev \
    && chmod +x /entrypoint*.sh

WORKDIR /workspace

ENTRYPOINT "/entrypoint.sh"