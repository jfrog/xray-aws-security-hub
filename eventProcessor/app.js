import _ from 'lodash';
import { Lambda, InvokeCommand } from '@aws-sdk/client-lambda';
import { fromUtf8 } from '@aws-sdk/util-utf8-node';
import { getLogger } from './logger.js'; // eslint-disable-line import/extensions

const logger = getLogger();

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

const lambdaInvoke = (issuesChunks) => {
  const command = new InvokeCommand({
    FunctionName: 'IssueProcessor',
    InvocationType: 'Event',
    Payload: fromUtf8(JSON.stringify(issuesChunks)),
  });
  return lambda.send(command);
};

export async function lambdaHandler(event) {
  const xrayEvent = JSON.parse(event.body);
  console.debug(`Event body: ${event.body}`);
  const hostName = event.headers.Hostname || 'hostname-was-not-set';
  if (hostName === 'hostname-was-not-set') {
    console.warn('Hostname was not set in the Xray Webhook header!');
  }
  try {
    const issues = createIssues(xrayEvent, hostName);
    const issuesChunks = createIssuesChunks(issues);
    logger.debug(JSON.stringify(issuesChunks));
    const promises = issuesChunks.map((chunk) => lambdaInvoke(chunk));
    const results = await Promise.allSettled(promises);
    logger.debug('IssueProcessor invoked', JSON.stringify(results));

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
