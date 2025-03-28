# Copyright 2025 Adam Chalkley
#
# https://github.com/atc0005/roots
#
# Licensed under the BSD License. See LICENSE file in the project root for
# full license information.
# REFERENCES
#
# https://github.com/golangci/golangci-lint#install
# https://github.com/golangci/golangci-lint/releases/latest

SHELL = /bin/bash

OUTPUTDIR 				:= release_assets

ASSETS_PATH				:= $(CURDIR)/$(OUTPUTDIR)

PROJECT_DIR				:= $(CURDIR)

GOCLEANCMD				=	go clean -mod=vendor ./...
GITCLEANCMD				= 	git clean -xfd

.DEFAULT_GOAL := help

  ##########################################################################
  # Targets will not work properly if a file with the same name is ever
  # created in this directory. We explicitly declare our targets to be phony
  # by making them a prerequisite of the special target .PHONY
  ##########################################################################

.PHONY: help
## help: prints this help message
help:
	@echo "Usage:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

.PHONY: lintinstall
## lintinstall: install common linting tools
# https://github.com/golang/go/issues/30515#issuecomment-582044819
lintinstall:
	@echo "Installing linting tools"

	@export PATH="${PATH}:$(go env GOPATH)/bin"

	@echo "Installing latest stable staticcheck version via go install command ..."
	go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck --version

	@echo Installing latest stable golangci-lint version per official installation script ...
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin
	golangci-lint --version

	@echo "Finished updating linting tools"

.PHONY: linting
## linting: runs common linting checks
linting:
	@echo "Running linting tools ..."

	@echo "Running go vet ..."
	@go vet -mod=vendor $(shell go list -mod=vendor ./... | grep -v /vendor/)

	@echo "Running golangci-lint ..."
	@golangci-lint --version
	@golangci-lint run

	@echo "Running staticcheck ..."
	@staticcheck --version
	@staticcheck $(shell go list -mod=vendor ./... | grep -v /vendor/)

	@echo "Finished running linting checks"

.PHONY: gotests
## gotests: runs go test recursively, verbosely
gotests:
	@echo "Running go tests ..."
	@go test -mod=vendor ./...
	@echo "Finished running go tests"

.PHONY: goclean
## goclean: removes local build artifacts, temporary files, etc
goclean:
	@echo "Removing object files and cached files ..."
	@$(GOCLEANCMD)

	@echo "Removing any existing release assets"
	@mkdir -p "$(ASSETS_PATH)"
	@rm -vf $(wildcard $(ASSETS_PATH)/*)

.PHONY: clean
## clean: alias for goclean
clean: goclean

.PHONY: gitclean
## gitclean: WARNING - recursively cleans working tree by removing non-versioned files
gitclean:
	@echo "Removing non-versioned files ..."
	@$(GITCLEANCMD)

.PHONY: pristine
## pristine: run goclean and gitclean to remove local changes
pristine: goclean gitclean

.PHONY: all
# https://stackoverflow.com/questions/3267145/makefile-execute-another-target
## all: run all applicable build steps
all: clean prep-assets
	@echo "Completed build process ..."

.PHONY: quick
## quick: alias for build recipe
quick: clean build
	@echo "Completed tasks for quick build"

.PHONY: build
## build: alias for prep-assets recipe
build: clean prep-assets
	@echo "Completed tasks for quick build"

.PHONY: podman-release-build
## podman-release-build: alias for prep-assets recipe
podman-release-build: clean prep-assets
	@echo "Completed tasks for release"

.PHONY: prep-assets
## prep-assets: prepare assets for release
prep-assets:
	@echo "Collecting assets for release ..."

	mkdir -vp release_assets

	cp -v mozilla_reports/*.csv release_assets/
	cp -v mozilla_reports/CDLA-Permissive-2.0.txt release_assets/

	cp -v certificates/*.pem release_assets/

	cp -v hashes/*.txt release_assets/

	@echo "Completed build tasks"

.PHONY: regenerate
## regenerate: regenerate project assets
regenerate:
	@echo "Regenerating project assets ..."
	@go generate

	@echo "Archiving files ..."
	@mkdir -vp mozilla_reports certificates hashes
	@mv -v *.csv mozilla_reports/
	@mv -v *.pem certificates/
	@mv -v *.txt hashes/

	@echo "Running project tests to validate generated assets ..."
	@go test ./...

	@echo "Completed assets regeneration tasks"
