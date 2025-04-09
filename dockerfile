# Use a lightweight Linux base with Python
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Copy all files into the container
COPY . .
RUN apt-get update && apt-get install -y file

# Run the script as default command
ENTRYPOINT ["python", "try.py"]
