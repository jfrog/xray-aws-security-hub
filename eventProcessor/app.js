import _ from 'lodash';
import { Lambda, InvokeCommand } from '@aws-sdk/client-lambda';
import { fromUtf8 } from '@aws-sdk/util-utf8-node';

const lambda = new Lambda({});

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
    statusCode: 202,
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

const createIssues = (event) => event.issues.map((issue) => ({
  watch_name: event.watch_name,
  policy_name: event.policy_name,
  created: event.created,
  ...issue,
}));

function createIssuesChunks(issues) {
  return _.chunk(issues, 10);
}

const asyncLambdaInvoke = async (issuesChunks) => {
  const command = new InvokeCommand({
    FunctionName: 'IssueProcessor',
    InvocationType: 'Event',
    Payload: fromUtf8(JSON.stringify(issuesChunks)),
  });
  const result = await lambda.send(command);
  console.log('IssueProcessor invoked', JSON.stringify(result));
};

export async function lambdaHandler(event) {
  const xrayEvent = JSON.parse(event.body);
  try {
    const issues = createIssues(xrayEvent);
    const issuesChunks = createIssuesChunks(issues);
    console.log(JSON.stringify(issuesChunks));
    const promises = [];
    for (const chunk of issuesChunks) {
      promises.push(asyncLambdaInvoke(chunk));
    }
    await Promise.allSettled(promises);

    return formatResponse({ message: `Issues processed: ${issues.length}` });
  } catch (error) {
    return formatError(error);
  }
}
