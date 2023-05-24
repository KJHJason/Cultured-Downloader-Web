# Below Docker file code for GCP Cloud Run
# Details: https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-service

# Use the official lightweight Python image
FROM python:3.12.0b1-slim

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED True

# Copy the dependency requirements to download 
# the dependencies to the working directory
COPY requirements.txt .

# Install the dependencies
RUN pip install -r requirements.txt

# Remove the python script and the requirements file
# after the dependencies are installed
RUN rm -f requirements.txt

# Copy local code to the container image
ENV APP_HOME /app
COPY src/ /app
WORKDIR $APP_HOME

# Set PORT env for flask app to Listen on port 8080
ENV PORT 8080

# Run the web service on container startup using hypercorn
# <filename>:<flask app variable name> which in this case is app:app
CMD exec hypercorn --bind :$PORT -w 4 app:app