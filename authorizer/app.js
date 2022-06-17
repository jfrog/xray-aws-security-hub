import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import _ from 'lodash';

const secretsManagerClient = new SecretsManagerClient();

const buildResponse = (isAuthorized, routeArn) => ({
  principalId: 'user',
  policyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Action: 'execute-api:Invoke',
        Effect: isAuthorized ? 'Allow' : 'Deny',
        Resource: routeArn,
      },
    ],
  },
});

// See https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html#http-api-lambda-authorizer.payload-format
// for event schema
export async function handler(event, context) {
  if (process.env.HAS_AUTH_TOKEN !== 'true') {
    console.debug('HAS_AUTH_TOKEN is not set to "true". Bypassing auth token check. Returning "Allow" policy.');
    return buildResponse(true, event.methodArn);
  }

  if (!_.has(event, 'authorizationToken') || _.isEmpty(event.authorizationToken)) {
    console.debug('Missing or empty event.authorizationToken');
    return buildResponse(false, event.methodArn);
  }

  try {
    const command = new GetSecretValueCommand({
      SecretId: process.env.SECRET_ID,
    });
    const output = await secretsManagerClient.send(command);

    if (output.SecretString === event.authorizationToken) {
      console.debug('event.authorizationToken match secret token');
      return buildResponse(true, event.methodArn);
    } else {
      console.debug('event.authorizationToken not match secret token');
      return buildResponse(false, event.methodArn);
    }
  } catch (err) {
    console.error(JSON.stringify(err));
    return buildResponse(false, event.methodArn);
  }
};
