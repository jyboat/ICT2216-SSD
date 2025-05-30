FROM python:3.12.6-slim

# Set working directory in the container
WORKDIR /ICT2216-Secure-Software-Development-SSD

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your code
COPY . .

# Expose port 80
EXPOSE 80

# Run the app
CMD ["python", "app.py"]