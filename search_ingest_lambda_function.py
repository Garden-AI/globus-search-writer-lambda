import globus_sdk
import boto3
import json


SEARCH_INDEX_UUID = '58e4df29-4492-4e7d-9317-b27eba62a911'

def get_secret():
    secret_name = "arn:aws:secretsmanager:us-east-2:509474786919:secret:GlobusAuthHelloWorldSecret-0q5j66"
    region_name = "us-east-2"

    # Create a Secrets Manager client
    session = boto3.session.Session()

    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    get_secret_value_response = client.get_secret_value(
        SecretId=secret_name
    )
    return eval(get_secret_value_response['SecretString'])



def lambda_handler(event, context):
    print("Event received: {} \n".format(event))
    print("event body: {} \n".format(event['body']))
    # Get the user's access token from the event data
    # access_token = event['access_token']
   
    # Get the CLIENT_ID and SECRET 
    globus_secrets = get_secret()

    # Validate the user's access token with Globus Auth
    auth_client = globus_sdk.ConfidentialAppAuthClient(
        globus_secrets['API_CLIENT_ID'], globus_secrets['API_CLIENT_SECRET'])

    print("established auth_client\n")

    token = event['headers']['authorization'].replace("Bearer ", "")

    auth_res = auth_client.oauth2_token_introspect(token, include="identities_set")
    print("auth_res: {} \n".format(auth_res))
    if not auth_res['active']:
        raise Exception("Invalid access token")

    # Get the document from the event data
    body = json.loads(event['body'])
    document = body['document_file']

    # Perform whatever policy checks we are going to do w/r/t write access
    # To determine whether this should be written

    # Create a Globus Search API client using the client credentials of the lambda function
    scopes = (globus_sdk.scopes.SearchScopes.all)
    cc_authorizer = globus_sdk.ClientCredentialsAuthorizer(auth_client, scopes)

    search_client = globus_sdk.SearchClient(authorizer=cc_authorizer)

    # Ingest the document file into Globus Search
    res = search_client.ingest(SEARCH_INDEX_UUID,document)

    return res.data

