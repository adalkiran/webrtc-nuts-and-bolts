#!/bin/bash

docker run --rm -it -v ${PWD}/docs:/docs --entrypoint /docs/mkdocs/prepare-mkdocs.sh squidfunk/mkdocs-material
docker run --rm -it -p 8000:8000 -v ${PWD}/docs/mkdocs:/docs squidfunk/mkdocs-material