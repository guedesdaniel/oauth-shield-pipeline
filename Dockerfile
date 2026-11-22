FROM apache/airflow:3.3.1

COPY requirements.txt /requirements.txt
# Pin Airflow to the image version so pip never upgrades/downgrades it by accident.
RUN pip install --no-cache-dir "apache-airflow==${AIRFLOW_VERSION}" -r /requirements.txt
