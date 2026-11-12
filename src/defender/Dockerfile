FROM python:3.10-slim

WORKDIR /app

# Install runtime dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy pre-trained 7-feature model bundles and registry
COPY models/ /app/models/

# Copy defender agent runtime
COPY src/defender/defender_agent.py /app/defender_agent.py

EXPOSE 8080

CMD ["python3", "-u", "/app/defender_agent.py"]
