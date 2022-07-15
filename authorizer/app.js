import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import _ from 'lodash';

import { getLogger } from './logger.js';

const logger = getLogger();

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
export async function handler(event) {
  if (process.env.HAS_AUTH_TOKEN !== 'true') {
    logger.error('HAS_AUTH_TOKEN is not set to "true". Bypassing auth token check. Returning "Allow" policy.');
    return buildResponse(true, event.methodArn);
  }

  if (!_.has(event, 'authorizationToken') || _.isEmpty(event.authorizationToken)) {
    logger.error('Missing or empty event.authorizationToken');
    return buildResponse(false, event.methodArn);
  }

  try {
    const command = new GetSecretValueCommand({
      SecretId: process.env.SECRET_ID,
    });
    const output = await secretsManagerClient.send(command);
    logger.debug(output);

    if (output.SecretString === event.authorizationToken) {
      logger.info('event.authorizationToken match secret token');
      return buildResponse(true, event.methodArn);
    }

    logger.error('event.authorizationToken not match secret token');
    return buildResponse(false, event.methodArn);
  } catch (err) {
    logger.error(err);
    return buildResponse(false, event.methodArn);
  }
}
