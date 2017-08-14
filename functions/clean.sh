#!/bin/bash

# Cleanup virtualenv post-deploy
find . -d -not -name ".." -not -name "." -not -name "tests" -not -name "data" -not -name "*.json" -not -name "__init__.py" -not -name "test_*.py" -not -name "*.json" -not -name "clean.sh" -not -name "main.py" -not -name "function.*" -not -name "utils.py" -not -name "requirements.txt" | xargs rm -fr &> /dev/null
find . -type f -name "*.py" -name "*.so" -not -name "data" -not -name "*.json" -not -name "__init__.py" -not -name "test_*.py" -not -name "*.json" -not -name "clean.sh" -not -name "main.py" -not -name "utils.py" -not -name "function.*" -not -name "requirements.txt" | xargs rm -fr &> /dev/null
