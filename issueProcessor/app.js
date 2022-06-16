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

async function sendSQSmessage(event) {
  // const queueURL = process.env.SQS_QUEUE_URL;
  const queueURL = 'https://sqs.us-west-1.amazonaws.com/096302395721/XraySourceQueue.fifo';
  const messageResponses = [];

  const params = {
    QueueUrl: queueURL,
    Entries: [],
  };

  for (const issue of event) {
    const myuuid = uuidv4();
    params.Entries.push({
      Id: myuuid,
      MessageAttributes: {
        MessageType: {
          DataType: 'String',
          StringValue: 'Final test - Daniel version',
        },
      },
      MessageDeduplicationId: Date.now().toString(),
      MessageGroupId: 'XrayPayload',
      MessageBody: JSON.stringify(issue),
    });
  }
  messageResponses.push({
    message: JSON.stringify(await sqsClient.send(new SendMessageBatchCommand(params))),
  });
  return messageResponses;
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
