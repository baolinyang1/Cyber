# Use a lightweight Linux base with Python
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Copy all files into the container
COPY . .

# Run the script as default command
ENTRYPOINT ["python", "try.py"]
