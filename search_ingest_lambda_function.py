import globus_sdk
import boto3
import json


SEARCH_INDEX_UUID = '847c9105-18a0-4ffb-8a71-03dd76dfcc9d'
# production search index is 847c9105-18a0-4ffb-8a71-03dd76dfcc9d
# dev search index is '58e4df29-4492-4e7d-9317-b27eba62a911'


def get_secret():
    secret_name = "arn:aws:secretsmanager:us-east-1:557062710055:secret:DLHub/GlobusSearchWriterClient-rgHEot"
    region_name = "us-east-1"

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


def _get_group_ids_groups_api(token):
    # Create a Groups client to retrieve the user's groups
    groups_client = globus_sdk.GroupsClient(
        authorizer=globus_sdk.AccessTokenAuthorizer(token))
    user_groups = groups_client.get_my_groups()
    user_group_ids = {_["id"] for _ in user_groups}
    return user_group_ids


def lambda_handler(event, context):
    # print("Event received: {} \n".format(event))
    # print("event body: {} \n".format(event['body']))

    # Get the user's access token from the event data
    # access_token = event['access_token']

    # Get the CLIENT_ID and SECRET
    globus_secrets = get_secret()

    # Validate the user's access token with Globus Auth
    auth_client = globus_sdk.ConfidentialAppAuthClient(
        globus_secrets['API_CLIENT_ID'], globus_secrets['API_CLIENT_SECRET'])

    token = event['headers']['authorization'].replace("Bearer ", "")

    auth_res = auth_client.oauth2_token_introspect(
        token, include="identities_set")
    # print("auth_res: {} \n".format(auth_res))
    if not auth_res['active']:
        raise Exception("Invalid access token")

    # Get dependent tokens
    dep_tokens = auth_client.oauth2_get_dependent_tokens(token)

    if "groups.api.globus.org" in dep_tokens.by_resource_server:
        groups_token = dep_tokens.by_resource_server["groups.api.globus.org"]["access_token"]
        user_group_ids = _get_group_ids_groups_api(groups_token)
        # print(f"User's group ids: {user_group_ids}")

    # Perform whatever policy checks we are going to do w/r/t write access
    # To determine whether this should be written
    # For example, check if the user is in the right group
    # DLHub didn't bother doing this, so for now we won't either.

    # Get the document from the event data
    body = json.loads(event['body'])
    document = body['document_file']

    # Create a Globus Search API client using the client credentials of the lambda function
    scopes = (globus_sdk.scopes.SearchScopes.all)
    cc_authorizer = globus_sdk.ClientCredentialsAuthorizer(auth_client, scopes)

    search_client = globus_sdk.SearchClient(authorizer=cc_authorizer)

    # Ingest the document file into Globus Search
    res = search_client.ingest(SEARCH_INDEX_UUID, document)

    return res.data
