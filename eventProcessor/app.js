import _ from 'lodash';
import { Lambda, InvokeCommand } from '@aws-sdk/client-lambda';
import { fromUtf8 } from '@aws-sdk/util-utf8-node';
import { getLogger } from './logger.js';

const logger = getLogger();

const lambda = new Lambda({});

const createIssues = (event, hostName) => event.issues.map((issue) => ({
  watch_name: event.watch_name,
  policy_name: event.policy_name,
  created: event.created,
  host_name: hostName,
  ...issue,
}));

const lambdaInvoke = (issuesChunks) => {
  const command = new InvokeCommand({
    FunctionName: 'IssueProcessor',
    InvocationType: 'Event',
    Payload: fromUtf8(JSON.stringify(issuesChunks)),
  });
  return lambda.send(command);
};

const HOSTNAME_NOT_SET = 'hostname-was-not-set';
const ASFF_BATCH_SIZE = 10;

export async function lambdaHandler(event) {
  const xrayEvent = JSON.parse(event.body);
  logger.debug(`Event body: ${event.body}`);

  const hostName = event.headers.Hostname || HOSTNAME_NOT_SET;
  if (hostName === HOSTNAME_NOT_SET) {
    logger.warn('Hostname was not set in the Xray Webhook header!');
  }

  let response;
  try {
    const issues = createIssues(xrayEvent, hostName);
    const issuesChunks = _.chunk(issues, ASFF_BATCH_SIZE);
    logger.debug(issuesChunks);
    const promises = issuesChunks.map((chunk) => lambdaInvoke(chunk));
    const results = await Promise.allSettled(promises);
    logger.debug('IssueProcessor invoked', { results });

    response = {
      statusCode: 202,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(`Number of processed issues is ${issues.length}`),
      isBase64Encoded: false,
    };
  } catch (err) {
    logger.error(err);
    response = {
      statusCode: err.statusCode,
      body: err,
    };
  }
  return response;
}
