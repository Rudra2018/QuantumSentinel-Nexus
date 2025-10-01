#!/bin/bash
# Enhanced UI startup script with port 8000
cd /app
python -m uvicorn main:app --host 0.0.0.0 --port 8000