import _ from 'lodash';
import { Lambda, InvokeCommand } from '@aws-sdk/client-lambda';
import { fromUtf8 } from '@aws-sdk/util-utf8-node';

const lambda = new Lambda({});
let response;

const createIssues = (event, hostName) => event.issues.map((issue) => ({
  watch_name: event.watch_name,
  policy_name: event.policy_name,
  created: event.created,
  host_name: hostName,
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

export async function lambdaHandler(event, context) {
  const xrayEvent = JSON.parse(event.body);
  console.log(JSON.stringify(event)); // testing where we can get the hostname
  console.log(JSON.stringify(context)); // testing where we can get the hostname
  const hostName = event.headers['X-Forwarded-For'];
  try {
    const issues = createIssues(xrayEvent, hostName);
    const issuesChunks = createIssuesChunks(issues);
    console.log(JSON.stringify(issuesChunks));
    const promises = [];
    for (const chunk of issuesChunks) {
      promises.push(asyncLambdaInvoke(chunk));
    }
    await Promise.allSettled(promises);

    response = {
      statusCode: 202,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(`Number of processed issues is ${issues.length}`),
      isBase64Encoded: false,
    };
  } catch (err) {
    response = {
      statusCode: err.statusCode,
      body: err,
    };
  }
  return response;
}
