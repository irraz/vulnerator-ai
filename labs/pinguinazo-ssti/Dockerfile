# pinguinazo-ssti — SSTI lab for Vulnerator-AI
# Inspired by the "Pinguinazo" machine from dockerlabs.es (© Mario's Penguin).
# Reimplemented as a standalone lab integrated into the vulnerator-ai network.
#
# Vulnerability: Flask/Jinja2 SSTI via render_template_string() with unsanitised input.
# Attack path: SSTI → RCE → reverse shell → sudo java → root.
#
# USE ONLY against this container in a controlled, authorized environment.

FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install Java (for sudo java privilege escalation) + netcat
RUN apt-get update && apt-get install -y --no-install-recommends \
        default-jdk-headless \
        netcat-openbsd \
        sudo \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged user
RUN useradd --create-home --shell /bin/bash pinguinazo && \
    echo 'pinguinazo:pinguinazo' | chpasswd

# sudo: pinguinazo can run java as root without password (the privesc vector)
RUN echo 'pinguinazo ALL=(ALL:ALL) NOPASSWD: /usr/bin/java' >> /etc/sudoers

# Flag
RUN echo 'CTF{pinguinazo_ssti_rce_sudo_java}' > /root/flag.txt && \
    chmod 400 /root/flag.txt

# Flask app
WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/app.py .

EXPOSE 5000

# Run as root so the Flask process can be reached for reverse shell escalation
# (the Flask user is pinguinazo, sudo escalates to root)
USER pinguinazo
CMD ["python3", "app.py"]
