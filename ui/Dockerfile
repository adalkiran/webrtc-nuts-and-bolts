# See here for image contents: https://github.com/devcontainers/images/blob/main/src/typescript-node/.devcontainer/Dockerfile
# See for available variants: https://github.com/devcontainers/images/tree/main/src/typescript-node
ARG VARIANT=22-bookworm
FROM mcr.microsoft.com/vscode/devcontainers/typescript-node:${VARIANT}

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive
#     && apt-get -y install --no-install-recommends <your-package-list-here>

# [Optional] Uncomment if you want to install an additional version of node using nvm
# ARG EXTRA_NODE_VERSION=10
# RUN su node -c "umask 0002 && ./usr/local/share/nvm/nvm.sh && nvm install ${EXTRA_NODE_VERSION}"

# [Optional] Uncomment if you want to install more global node modules
# RUN su node -c "npm install -g <your-package-list-here>"

WORKDIR /workspace

ENTRYPOINT yarn install && npm run start