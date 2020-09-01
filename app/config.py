import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    ENVIRONMENT = os.environ.get('ENVIRONMENT')
    LOGDNA_APIKEY = os.environ.get('LOGDNA_APIKEY')
    LOGDNA_LOGHOST = os.environ.get('LOGDNA_LOGHOST')
    SERVERNAME = os.environ.get('SERVERNAME')
    IAM_ENDPOINT = os.environ.get("IAM_ENDPOINT")
    REDIS_HOST = os.environ.get("REDIS_HOST")
    REDIS_PORT = os.environ.get("REDIS_PORT")
    REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
    REDIS_CERT_CRN = os.environ.get("REDIS_CERT_CRN")
    CERT_MANAGER_ENDPOINT = os.environ.get("CERT_MANAGER_ENDPOINT")
    IBMCLOUD_APIKEY = os.environ.get("IBMCLOUD_APIKEY")  
