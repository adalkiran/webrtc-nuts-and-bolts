# **1. RUNNING IN DEVELOPMENT MODE**

* Clone this repo.

* Learn your host machine's LAN IP address:

```console
$ ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'

192.168.***.***
```

* Open [backend/config.yml](../backend/config.yml) file, write your LAN IP address into server/udp/dockerHostIp section.

* If you don't have VS Code and [Remote Development extension pack](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.vscode-remote-extensionpack) installed, install them. [This link](https://code.visualstudio.com/docs/remote/containers) can be helpful.

* Start VS Code, open the cloned folder of "webrtc-nuts-and-bolts".

* Press <kbd>F1</kbd> and select **"Remote Containers: Open Folder in Container..."** then select "backend" folder in "webrtc-nuts-and-bolts".

<img alt="Open folder in container" src="images/01-01-open-folder-in-container.png" style="width: 500px;max-width:50%"></img>

<img alt="Select &quot;backend&quot; folder" src="images/01-02-select-folder.png" style="width: 500px;max-width:50%"></img>

* This command creates (if don't exist) required containers in Docker, then connects inside of webrtcnb-backend container for development and debugging purposes.

* You will see this notification while building image and starting container. If you click on this notification, you will see a log similar to image below.

<img alt="Starting Dev Container small" src="images/01-03-starting-dev-container-small.png" style="width: 500px;max-width:50%"></img>

![Starting Dev Container log](images/01-04-starting-dev-container-log.png)

* When webrtcnb-backend container has been built and started, VS Code will ask you for some required installations related to Go language, click "Install All" for these prompts.

<img alt="Install Go Dependencies small" src="images/01-05-install-go-deps-small.png" style="width: 500px;max-width:50%"></img>

* After clicking "Install All", you will see installation logs similar to image below.

<img alt="Install Go Dependencies log" src="images/01-06-install-go-deps-log.png" style="width: 500px;"></img>

* When you see "You are ready to Go. :)" message in the log, you can press <kbd>F5</kbd> to run and debug our server inside the container. VS Code can ask for installing other dependencies (like "dlv"), click on "Install" again. If VS Code asked for some extra installations, after installation you may need to press <kbd>F5</kbd> again.

* You can switch to **"DEBUG CONSOLE"** tab at bottom, you will be able to see the output of running server application:

![Backend initial output](images/01-07-backend-initial-output.png)

* Now your backend server is ready to accept requests from browser!

<br>

---

<div align="right">

[&lt;&nbsp;&nbsp;Previous chapter: INFRASTRUCTURE](./00-INFRASTRUCTURE.md)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Next chapter: BACKEND INITIALIZATION&nbsp;&nbsp;&gt;](./02-BACKEND-INITIALIZATION.md)

</div>
