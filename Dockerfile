FROM python:3.12.6-slim

# Install build dependencies for mysqlclient
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory in the container
WORKDIR /ICT2216-SSD

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your code
COPY . .

# Expose port 80
EXPOSE 443

# debug
ENV PYTHONUNBUFFERED=1

# Run the app
CMD ["python", "app.py"]