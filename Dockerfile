FROM ubuntu:18.04
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
RUN apt-get update && apt-get install -y apt-transport-https python3.6 python3-pip git jq curl wget tar socat
RUN curl -fsSL https://clis.cloud.ibm.com/install/linux | sh
RUN ibmcloud config --check-version=false
WORKDIR /app
COPY . .
COPY requirements.txt .
RUN pip3 install -r requirements.txt
ENV FLASK_APP=ocp-realtime-02cn.py
EXPOSE 8220
ENTRYPOINT [ "python3" ]

CMD [ "app/ocp-realtime-02cn.py" ]