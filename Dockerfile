FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV SOC_AGENT_MODE=replay
CMD ["python", "-m", "scripts.run_samples"]
