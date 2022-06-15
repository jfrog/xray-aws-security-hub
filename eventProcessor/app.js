import _ from 'lodash';

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

export async function lambdaHandler(event) {
  try {
    const issues = createIssues(event);
    const issuesChunks = createIssuesChunks(issues);
    // TODO invoke another lambda
    return formatResponse(issuesChunks);
  } catch (error) {
    return formatError(error);
  }
}
