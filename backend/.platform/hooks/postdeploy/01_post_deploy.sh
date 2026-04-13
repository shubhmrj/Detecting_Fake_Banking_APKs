#!/bin/bash

# Elastic Beanstalk post-deployment hook script
# This script runs after the application is deployed

source $PYTHONPATH/activate 2>/dev/null

# Create necessary directories
mkdir -p /var/app/current/logs
mkdir -p /var/app/current/uploads

# Set proper permissions
chown -R webapp:webapp /var/app/current/logs 2>/dev/null
chmod -R 755 /var/app/current/logs

# Run any database migrations if needed
# python /var/app/current/backend/db_migrations.py

echo "Post-deployment tasks completed"
