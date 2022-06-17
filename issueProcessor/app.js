import { SendMessageBatchCommand, SQSClient } from '@aws-sdk/client-sqs';
import { v4 as uuidv4 } from 'uuid';

const sqsClient = new SQSClient({});

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
  console.error(response);
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
  console.log(JSON.stringify(response));
  return response;
};

const sendSQSmessage = async (event) => {
  const messageResponses = [];

  const params = {
    QueueUrl: process.env.SQS_QUEUE_URL,
    Entries: [],
  };

  for (const issue of event) {
    const uuid = uuidv4();
    params.Entries.push({
      Id: uuid,
      MessageDeduplicationId: uuid,
      MessageGroupId: 'XrayPayload',
      MessageBody: JSON.stringify(issue),
    });
  }
  return await sqsClient.send(new SendMessageBatchCommand(params));
}

export async function lambdaHandler(event) {
  let results;
  try {
    results = await sendSQSmessage(event);
  } catch (error) {
    return formatError(error);
  }
  return formatResponse(results);
}
