# **0. INFRASTRUCTURE**

When you run the docker-compose.yml file individually (for production mode) or docker-compose.yml with docker-compose.dev.yml (for development mode, with VS Code, explained in [Development Mode: VS Code Remote - Containers](../README.md#dev-mode)), it will create two containers webrtcnb-ui (with [ui/Dockerfile](../ui/Dockerfile)) and webrtcnb-backend (with [backend/Dockerfile](../backend/Dockerfile))

## **0.1. Container webrtcnb-ui (ui/Dockerfile) is booting up...**

<sup>Related part of [docker-compose.yml](../docker-compose.yml):</sup>

```yml
...
  ui:
    image: webrtc-nuts-and-bolts/ui
    container_name: webrtcnb-ui
    build:
      context: ui # Dockerfile location
      args:
        - VARIANT:22-bookworm
    volumes:
      # Mount the root folder that contains .git
      - "./ui:/workspace:cached"
    ports:
      - "8080:8080" # Port expose for UI Webpack Dev Server
...
```

<sup>Related part of [ui/Dockerfile](../ui/Dockerfile):</sup>

```dockerfile
ARG VARIANT=22-bookworm
FROM mcr.microsoft.com/vscode/devcontainers/typescript-node:${VARIANT}

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive

WORKDIR /workspace

ENTRYPOINT yarn install && npm run start
```

This file inherits from *mcr.microsoft.com/vscode/devcontainers/typescript-node:22-bookworm* image which come up with an environment includes NodeJS, Webpack, Webpack Dev Server, TypeScript, over Debian "bookworm" Linux Distribution. We don't need to install related things manually.

While building the custom image (once):

* Runs *apt-get update* to update installed OS dependencies

While every time of the container starting up:

* Boots up *webrtcnb-ui* container
* Maps */ui* directory (in host machine) to */workspace* (in container)
* Exposes container's *8080* port to the host (so we can browse the website served in the container)
* Sets */workspace* as our working directory
* Calls *yarn install* to install NodeJS dependencies defined in [package.json](../ui/package.json) (this step can take some time)
* Runs the Webpack Dev Server by calling *npm run start* then it starts to serve the website on http://localhost:8080 (configured in [docker-compose.yml](../docker-compose.yml)) (You don't need to do anything to run the UI server manually.)

## **0.2. Container webrtcnb-backend (backend/Dockerfile) is booting up...**

<sup>Related part of [docker-compose.yml](../docker-compose.yml):</sup>

```yml
...
  backend:
    image: webrtc-nuts-and-bolts/backend
    container_name: webrtcnb-backend
    build:
      context: backend # Dockerfile location
      args:
        - VARIANT:1.23.0-bookworm
    # [Optional] Required for ptrace-based debuggers like C++, Go, and Rust
    cap_add:
      - SYS_PTRACE
    security_opt:
      - seccomp:unconfined
    volumes:
      # Mount the root folder that contains .git
      - "./backend:/workspace:cached"
    ports:
      - "8081:8081" # Port expose for backend WebSocket
      - "15000:15000/udp" # Port expose for backend UDP end
...
```

<sup>Related part of [backend/Dockerfile](../backend/Dockerfile):</sup>

```dockerfile
ARG VARIANT=1.23.0-bookworm
FROM golang:${VARIANT}

COPY entrypoint.sh entrypoint-dev.sh /

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install libvpx-dev libogg-dev libvorbis-dev libopus-dev portaudio19-dev \
    && chmod +x /entrypoint*.sh

WORKDIR /workspace

ENTRYPOINT "/entrypoint.sh"
```

This file inherits from *golang:1.23.0-bookworm* image which come up with an environment includes Go language support, libraries for processing VP8 (video) and OPUS (audio) encoding, on Debian "bookworm" Linux Distribution. We don't need to install related things manually.

While building the custom image (once):

* Embeds [entrypoint.sh](../backend/entrypoint.sh) and [entrypoint-dev.sh](../backend/entrypoint-dev.sh) files into the custom image
* Runs *apt-get update* to update installed OS dependencies
* Installs [libvpx](https://en.wikipedia.org/wiki/Libvpx) and other codec libraries. Currently we use the libvpx one only.
* Allows the entrypoint shell script files to be executed.

While every time of the container starting up:

* Boots up *webrtcnb-backend* container
* Maps */backend* directory (in host machine) to */workspace* (in container)
* Exposes container's *8081* port to the host (so our browser can access the websocket served in the container)
* Exposes container's *15000* port (only for UDP) to the host (so our browser can access our UDP listener in the container)
* Sets */workspace* as our working directory
* Executes *[entrypoint.sh](../backend/entrypoint.sh)* or *[entrypoint-dev.sh](../backend/entrypoint-dev.sh)* according to which mode (production or development) it runs.

<sup>Related part of [backend/entrypoint.sh](../backend/entrypoint.sh):</sup>

```sh
echo "Downloading dependent Go modules..."
go mod download -x
echo "Running application..."
cd src
go run .
```

<sup>Related part of [backend/entrypoint-dev.sh](../backend/entrypoint-dev.sh):</sup>

```sh
echo "Downloading dependent Go modules..."
go mod download -x
echo "Running into Waiting loop..."
tail -f /dev/null
```

* Both entrypoint.sh and entrypoint-dev.sh files call *go mod download -x* to download and install related Go language dependencies defined in [go.mod](../backend/go.mod) (this step can take some time)

    * If it is in production mode, it calls
    <br>*go run .*
    <br>to start our server immediately.
    * If it is in development mode, it calls
    <br>*tail -f /dev/null*
    <br>to put the container's process in an infinite loop, so container won't exit. At this time, our server won't start immediately. You should start it manually by opening the backend folder with VS Code's **"Remote Containers: Open Folder in Container..."** option and pressing <kbd>F5</kbd> in VS Code window. This option was designed for debugging purposes, so you are free to stop and start your server application manually whenever you want.

## **0.3. Checking that everything is ready to use**

If you followed up related instructions correctly, you can see outputs like these:

* Checking the containers are running:

Expected output (can vary)

```console
$ docker ps

CONTAINER ID   IMAGE                           COMMAND                  CREATED       STATUS        PORTS                                              NAMES
07f0c553d64e   webrtc-nuts-and-bolts/backend   "/bin/sh -c 'echo Co…"   11 days ago   Up 42 hours   0.0.0.0:8081->8081/tcp, 0.0.0.0:15000->15000/udp   webrtcnb-backend
31f3a54b7498   webrtc-nuts-and-bolts/ui        "/bin/sh -c 'yarn in…"   11 days ago   Up 2 days     0.0.0.0:8080->8080/tcp                             webrtcnb-ui
```

* Checking the UI web server container is running:

If you can see *｢wdm｣: Compiled successfully.* in latest output, it has started serving successfully.

Expected output (can vary) (you can exit by pressing <kbd>CTRL+C</kbd>)

```console
$ docker logs -f webrtcnb-ui

***
ℹ ｢wds｣: Project is running at http://0.0.0.0:8080/
ℹ ｢wds｣: webpack output is served from /
ℹ ｢wds｣: Content not from webpack is served from ./dist
｢wdm｣: asset index.bundle.js 1.71 MiB [emitted] (name: index)
asset index.html 414 bytes [emitted]
runtime modules 27.4 KiB 13 modules
cacheable modules 613 KiB
  modules by path ./node_modules/webpack-dev-server/ 21.2 KiB 12 modules
  modules by path ./node_modules/html-entities/lib/*.js 61 KiB 5 modules
  modules by path ./node_modules/webpack/hot/*.js 4.3 KiB 4 modules
  modules by path ./node_modules/sdp-transform/lib/*.js 21 KiB 4 modules
  modules by path ./node_modules/url/ 37.4 KiB
    ./node_modules/url/url.js 22.8 KiB [built] [code generated]
    + 2 modules
  modules by path ./node_modules/querystring/*.js 4.51 KiB
    ./node_modules/querystring/index.js 127 bytes [built] [code generated]
    + 2 modules
  + 6 modules
./node_modules/webpack/hot/ sync nonrecursive ^\.\/log$ 170 bytes [built] [code generated]
webpack 5.72.0 compiled successfully in 4333 ms
｢wdm｣: Compiled successfully.
```

* Checking the backend container is running (for development mode):

If you can see *Running into Waiting loop...* in latest output, it has started successfully and waiting for you to start the server application manually.

```sh
$ docker logs -f webrtcnb-backend

Container started
Downloading dependent Go modules...

...

Running into Waiting loop...
```

<br>

---

<div align="right">

[&lt;&nbsp;&nbsp;Documentation Index](./README.md)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Next chapter: RUNNING IN DEVELOPMENT MODE&nbsp;&nbsp;&gt;](./01-RUNNING-IN-DEV-MODE.md)

</div>