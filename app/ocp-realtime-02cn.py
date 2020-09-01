import requests, json, urllib, random, string, ssl, os, logging, config, datetime, ast, redis, subprocess
from flask import Flask, request
from flask_restful import Api, Resource
from config import Config
from logging.config import dictConfig
from logdna import LogDNAHandler
from subprocess import call, check_output, Popen, PIPE
import xmltodict

dictConfig({
            'version': 1,
            'formatters': {
                'default': {
                    'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
                }
            },
            'handlers': {
                'logdna': {
                    'level': logging.DEBUG,
                    'class': 'logging.handlers.LogDNAHandler',
                    'key': os.environ.get('LOGDNA_APIKEY'),
                    'options': {
                        'app': 'ocp-realtime-02cn.py',
                        'tags': os.environ.get('SERVERNAME'),
                        'env': os.environ.get('ENVIRONMENT'),
                        'url': os.environ.get('LOGDNA_LOGHOST'),
                        'index_meta': True,
                    },
                 },
            },
            'root': {
                'level': logging.DEBUG,
                'handlers': ['logdna']
            }
        })

HOST = '0.0.0.0'
PORT = 8220

app = Flask(__name__)
app.logger.debug("Starting zero to cloud native openshift realtime")

app.config.from_object(Config)


api = Api(app)

def getRequestId():
    letters = string.ascii_uppercase
    return ''.join(random.choice(letters) for i in range(6))

def getiamtoken(apikey):
    app.logger.debug("try getiamtoken")
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic Yng6Yng=',
    }
    parms = {"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": apikey}

    try:
        resp = requests.post(app.config['IAM_ENDPOINT'] + "/identity/token?" + urllib.parse.urlencode(parms), headers=headers, timeout=30)
    except:
        #try twice
        try:
            resp = requests.post(app.config['IAM_ENDPOINT'] + "/identity/token?" + urllib.parse.urlencode(parms), headers=headers, timeout=30)
            resp.raise_for_status()
        except requests.exceptions.ConnectionError as errc:
            quit()
        except requests.exceptions.Timeout as errt:
            quit()
        except requests.exceptions.HTTPError as errb:
            quit()

    iam = resp.json()
    return iam 

def getRedisCert(reqid, apikey):
    app.logger.debug("{} Starting to get Redis Certificate ")
    iamToken = getiamtoken(apikey)
    certManagerEndpoint = app.config['CERT_MANAGER_ENDPOINT']
    app.logger.debug("{} cert manager endpoint {}".format(reqid, certManagerEndpoint))
    header = {
        'accept': 'application/json',
        'Authorization': 'Bearer ' + iamToken["access_token"]
    }
    redis_crn = app.config['REDIS_CERT_CRN']
    url = certManagerEndpoint+'/api/v2/certificate/'+urllib.parse.quote_plus(redis_crn)
    
    response = requests.get(url,headers=header)
    json_response = json.loads(response.text)
    cert_file = open("redis-crt.pem", "wt")
    n = cert_file.write(json_response['data']['content'])
    cert_file.close()
    
    return

def getClusterServerURL(apikey, clustername):
    header = {
        'accept': 'application/json',
        'Authorization': getiamtoken(apikey)["access token"]
    }
    response = requests.get('https://containers.cloud.ibm.com/global/v1/clusters/'+str(clustername),headers=header)
    json_response = json.loads(response.text)
    return json_response['serverURL']

def getClusterAuthToken(reqid, apikey, clustername):
    app.logger.info("{} Starting to get cluster auth token ".format(reqid))
    masterURL = getClusterServerURL(apikey, clustername)
    app.logger.info("{} Master URL = {}".format(reqid, masterURL))
    response = requests.get(masterURL+'/.well-known/oauth-authorization-server')
    json_response = json.loads(response.text)
    authorization_endpoint = json_response['authorization_endpoint']
    app.logger.debug("{} authorization endpoint = {}".format(reqid, authorization_endpoint))
    curlCommand = "curl -u 'apikey:" + apikey +"' -H 'X-CSRF-Token: a' "+ authorization_endpoint + "'?client_id=openshift-challenging-client&response_type=token' -vvv"
    output = subprocess.getstatusoutput(curlCommand)
    str_output = json.dumps(output)
    app.logger.debug("{} output for getting token = {}".format(reqid, str_output))
    accessTokenIndex = str_output.find('access_token')
    expiresInIndex = str_output.find('expires_in')
    auth_token = str_output[accessTokenIndex+13:(expiresInIndex - 1)]
    return auth_token

def getOCPVersions(reqid):
    return_versions = []
    try:
        app.logger.info("{} Going to get versions of openshift".format(reqid))
        # getRedisCert(reqid, app.config["IBMCLOUD_APIKEY"])
        r = redis.StrictRedis(
            host=app.config['REDIS_HOST'], 
            port=app.config['REDIS_PORT'], 
            password=app.config['REDIS_PASSWORD'],
            ssl=True,
            ssl_ca_certs='redis-crt.pem',
            db=0,
            decode_responses=True)
        versions_str = r.get("openshift_versions")
        return_versions = ast.literal_eval(versions_str)
        app.logger.debug("{} cached returned versions = {}".format(reqid, return_versions))
    except Exception as e:
        app.logger.error("Problem getting cached versions {}".format(e))
        pass
    return return_versions

class GetOCPToken(Resource):
    def get(self):
        try:
            input_json_data = request.get_json()
            app.logger.debug("get OCP input json data {}".format(input_json_data))
            if "reqid" in input_json_data:
                reqid = input_json_data['reqid']
            else:
                reqid=getRequestId()
            app.logger.debug("get OCP token")
            app.logger.info("{} Starting Openshift Realtime Get OCP Token.".format(reqid))
            apikey=input_json_data['apikey']
            clustername=input_json_data['clustername']
            
            authToken = getClusterAuthToken(reqid, apikey, clustername)
            server = getClusterServerURL(apikey, clustername)
            app.logger.debug("{} Got this ocp token {}".format(reqid, authToken))
            app.logger.debug("{} Got this as the server url {}".format(reqid, server))
            return {
                "Status":"Successfully retrieved ocp token for request id"+reqid,
                "token": authToken,
                "server": server
            }
        except Exception as e:
            app.logger.error("{} Error Openshift Realtime Get OCP Token - Problem getting list of versions {}".format(reqid, e))
            return {
                "Status":"Problem getting token for request id "+reqid
            }

class GetOCPVersions(Resource):
    def get(self):
        try:
            input_json_data = request.get_json()
            app.logger.debug("get OCP input json data {}".format(input_json_data))
            if "reqid" in input_json_data:
                reqid = input_json_data['reqid']
            else:
                reqid=getRequestId()
            
            app.logger.info("{} Starting Openshift Realtime Get OCP Versions.".format(reqid))
            versions=getOCPVersions(reqid)
            app.logger.debug("{} Got this list of versions {}".format(reqid, versions))
            return {
                "Status":"Successfully retrieved a list of versions for request id"+reqid,
                "Versions": versions
            }
        except Exception as e:
            app.logger.error("{} Error Openshift Realtime Get OCP Versions - Problem getting list of versions {}".format(reqid, e))
            return {
                "Status":"Problem getting list of versions for request id "+reqid
            }


api.add_resource(GetOCPVersions, '/api/v1/getOCPVersions/')
api.add_resource(GetOCPToken, '/api/v1/getOCPToken/')
getRedisCert("START-OCP-REALTIME ", app.config["IBMCLOUD_APIKEY"])

if __name__ == '__main__':
    app.run(host=HOST, port=PORT, threaded=True, debug=True)