// eslint-disable-next-line import/extensions
import SQS from 'aws-sdk/clients/sqs.js';
import _ from 'lodash';
import { v4 as uuidv4 } from 'uuid';

const sqs = new SQS();

const formatError = function (error) {
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

const formatResponse = function (body) {
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

async function createIssuesList(event) {
  let result = {};
  const issuesArray = [];

  const additionalFields = {
    watch_name: event.watch_name,
    policy_name: event.policy_name,
  };

  event.issues.forEach(injectFields);
  function injectFields(issue) {
    result = {
      ...issue,
      ...additionalFields,
    };
    issuesArray.push({
      issue: JSON.stringify(result),
    });
  }
  const lodashSpiltArray = _.chunk(issuesArray, 3);
  console.log(JSON.stringify(lodashSpiltArray));
  return lodashSpiltArray;
}

async function sendSQSmessage(issuesArray) {
  // let queueURL = process.env.SQS_QUEUE_URL;
  const queueURL = 'https://sqs.us-west-1.amazonaws.com/096302395721/XraySourceQueue.fifo';
  const messageResponses = [];

  for (const issue of issuesArray) {
    const params = {
      QueueUrl: queueURL,
      Entries: [],
    };

    for (const message of issue) {
      const myuuid = uuidv4();
      params.Entries.push({
        Id: myuuid,
        MessageAttributes: {
          MessageType: {
            DataType: 'String',
            StringValue: 'Final test',
          },
        },
        MessageDeduplicationId: Date.now().toString(),
        MessageGroupId: 'XrayPayload',
        MessageBody: JSON.stringify(message),
      });
    }
    messageResponses.push({
      message: JSON.stringify(await sqs.sendMessageBatch(params).promise()),
    });
  }
  return messageResponses;
}

export async function lambdaHandler(event) {
  let issuesArray;
  let messagesSent;
  try {
    issuesArray = await createIssuesList(event);
    messagesSent = await sendSQSmessage(issuesArray);
  } catch (error) {
    return formatError(error);
  }
  return formatResponse(messagesSent);
}
