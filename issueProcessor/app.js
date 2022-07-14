import { SendMessageBatchCommand, SQSClient } from '@aws-sdk/client-sqs';
import { v4 as uuidv4 } from 'uuid';
import { getLogger } from './logger.js'; // eslint-disable-line import/extensions

const logger = getLogger();

const sqsClient = new SQSClient();

const formatError = (error) => {
  const response = {
    statusCode: error.statusCode,
    headers: {
      'Content-Type': 'text/plain',
      'x-amzn-ErrorType': error.code,
    },
    isBase64Encoded: false,
    body: `${error.code}: ${error.message}`,
  };
  logger.error(response);
  return response;
};

const formatResponse = (body) => {
  const response = {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
    },
    isBase64Encoded: false,
    multiValueHeaders: {
      'X-Custom-Header': ['JFrog', 'Xray'],
    },
    body,
  };
  logger.debug(response);
  return response;
};

const sendSQSmessage = async (event) => {
  const params = {
    QueueUrl: process.env.SQS_QUEUE_URL,
    Entries: event.map((issue) => {
      const uuid = uuidv4();
      return {
        Id: uuid,
        MessageDeduplicationId: uuid,
        MessageGroupId: 'XrayPayload',
        MessageBody: JSON.stringify(issue),
      };
    }),
  };

  return await sqsClient.send(new SendMessageBatchCommand(params));
};

export async function lambdaHandler(event) {
  logger.debug('event', { event });
  try {
    const results = await sendSQSmessage(event);
    logger.debug('sendSQSmessage results:', { results });
    return formatResponse(results);
  } catch (error) {
    return formatError(error);
  }
}
