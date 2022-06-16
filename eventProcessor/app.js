import _ from 'lodash';
import aws from 'aws-sdk';

const lambda = new aws.Lambda();

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

const createIssues = (event) => event.issues.map((issue) => ({
  watch_name: event.watch_name,
  policy_name: event.policy_name,
  ...issue,
}));

function createIssuesChunks(issues) {
  return _.chunk(issues, 10);
}

const asyncLambdaInvoke = async (issuesChunks) => {
  const result = await lambda
    .invoke({
      FunctionName: 'IssueProcessor',
      InvocationType: 'Event',
      Payload: JSON.stringify(issuesChunks),
    })
    .promise();
  console.log('IssueProcessor invoked', JSON.stringify(result));
};

export async function lambdaHandler(event) {
  try {
    const issues = createIssues(event);
    const issuesChunks = createIssuesChunks(issues);
    const promises = [];
    for (const chunk of issuesChunks) {
      promises.push(asyncLambdaInvoke(chunk));
    }
    await Promise.allSettled(promises);

    return formatResponse(promises.length);
  } catch (error) {
    return formatError(error);
  }
}
