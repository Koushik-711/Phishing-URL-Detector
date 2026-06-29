# Use an official lightweight Python image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /code

# Copy the requirements file and install dependencies
COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# Copy all local project files into the container
COPY . .

# Expose port 7860 (Hugging Face Spaces default internal port)
EXPOSE 7860

# Run Uvicorn pointing to port 7860
CMD ["uvicorn", "main.py:app", "--host", "0.0.0.0", "--port", "7860"]