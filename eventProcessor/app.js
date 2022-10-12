import _ from 'lodash';
import { Lambda, InvokeCommand } from '@aws-sdk/client-lambda';
import { fromUtf8 } from '@aws-sdk/util-utf8-node';
import axios from 'axios';
import { getLogger } from './logger.js';
import { validateSchema } from './schema.js';

const logger = getLogger();
const REGION = process.env.AWS_REGION;
const SECURITY_HUB_REGION = process.env.SECURITY_HUB_REGION || REGION;

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

const axiosClient = axios.create({
  baseURL: 'https://heapanalytics.com/api',
  headers: {
    'Content-Type': 'application/json',
    accept: 'application/json',
  }
});

const sendCallHomeData = async (callHomePayload) => {
  const APP_HEAPIO_APP_ID = process.env.APP_HEAPIO_APP_ID;
  let response;
  if (!APP_HEAPIO_APP_ID) {
    logger.warn('Missing APP_HEAPIO_APP_ID env var. No data sent.');
    return;
  }

  try {
    const body = {
      app_id: APP_HEAPIO_APP_ID,
      identity: callHomePayload.jpd_url,
      event: 'process-xray-payload-security-hub',
      properties: callHomePayload,
    };

    logger.info('Sending data to Heap.io, path: /track', { body });

    response = await axiosClient.post('/track', body);
  } catch (e) {
    logger.error('Failed to send data to Heap.io', { e });
  }
  return response;
};

const HOSTNAME_NOT_SET = 'hostname-was-not-set';
const ASFF_BATCH_SIZE = 10;

export async function lambdaHandler(event) {
  const hostName = event.headers.Hostname || HOSTNAME_NOT_SET;
  if (hostName === HOSTNAME_NOT_SET) {
    logger.warn('Hostname was not set in the Xray Webhook header!');
  }

  const xrayEvent = JSON.parse(event.body);
  logger.debug(`Event body: ${event.body}`);

  let response;
  try {
    const validatedEvent = await validateSchema(xrayEvent);

    const issues = createIssues(validatedEvent, hostName);
    const issuesChunks = _.chunk(issues, ASFF_BATCH_SIZE);
    logger.debug('Issue chunks', { issuesChunks });
    const promises = issuesChunks.map((chunk) => lambdaInvoke(chunk));
    const results = await Promise.allSettled(promises);
    logger.debug('IssueProcessor invoked', { results });

    try {
      const callHomePayload = {
        integration: 'xray-aws-security-hub',
        region: SECURITY_HUB_REGION,
        xray_issues_received: event.length,
        messages_sent_to_issue_processor: results.filter((result) => (result.status === 'fulfilled')).length,
        failed_messages: results.filter((result) => (result.status === 'rejected')).length,
        action: 'process-xray-payload-security-hub',
        jpd_url: `https://${hostName}`,
      };
      await sendCallHomeData(callHomePayload);
      logger.info('HeapIO request has been sent.');
    } catch (e) {
      logger.warn(`Error while sending info to HeapIO. ${e}`);
    }

    response = {
      statusCode: 202,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(`Number of processed issues is ${issues.length}`),
      isBase64Encoded: false,
    };
  } catch (err) {
    err.statusCode ??= 500;
    logger.error('failed to process Xray event', { err });
    response = {
      statusCode: err.statusCode,
      body: err.toString(),
    };
  }
  return response;
}
