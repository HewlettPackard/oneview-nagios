FROM python:3.6-alpine

# Set proxy
ARG http_proxy
ENV HTTP_PROXY=$http_proxy
ENV HTTPS_PROXY=$http_proxy

# Copy requirements.txt file to install dependencies
COPY requirements.txt /plugin/requirements.txt

WORKDIR /plugin

# Install Dependencies
RUN pip install -r requirements.txt

# Run the plugin
CMD ["python","main.py","-i","config/input_config_nagios.json"]
