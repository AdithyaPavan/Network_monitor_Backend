# ---- Use Python 3.10 base image ----
FROM python:3.10-slim

# ---- Install traceroute & dependencies ----
RUN apt-get update && apt-get install -y traceroute iputils-ping && apt-get clean

# ---- Set working directory ----
WORKDIR /app

# ---- Copy all project files ----
COPY . .

# ---- Install Python dependencies ----
RUN pip install --no-cache-dir -r requirements.txt

# ---- Expose Flask default port ----
EXPOSE 5000

# ---- Start with Gunicorn ----
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "network_monitor:app"]
