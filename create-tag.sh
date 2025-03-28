#!/bin/bash
# Git Tag Conditional Creation Script
# Author: ChatGPT (OpenAI)
# Date: 2025-02-09
# License: BSD
# Description: This script creates a new Git tag for the current commit
#              only if no existing tags already reference it.

TAG_NAME="$1"

if ! git tag -l --points-at HEAD | grep -q .; then
    git tag "$TAG_NAME"
    echo "Tag $TAG_NAME created."
else
    echo "A tag already exists for this commit."
fi
