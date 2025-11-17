# 1. Start with the official AWS base image for Python 3.12 Lambda
FROM public.ecr.aws/lambda/python:3.12

# 2. Copy our ML models from our project folder into the container's "/var/task/" directory
COPY isolation_forest.joblib ${LAMBDA_TASK_ROOT}/
COPY tfidf_vectorizer.joblib ${LAMBDA_TASK_ROOT}/

# 3. Copy our Python "brain" code into the container
COPY lambda_function.py ${LAMBDA_TASK_ROOT}/

# 4. Copy the requirements file
COPY requirements.txt ${LAMBDA_TASK_ROOT}/

# 5. Run pip install to get all our libraries *inside* the container
RUN pip install -r requirements.txt

# 6. Tell Lambda what function to run when it's triggered
CMD [ "lambda_function.lambda_handler" ]