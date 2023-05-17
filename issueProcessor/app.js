import { SendMessageBatchCommand, SQSClient } from '@aws-sdk/client-sqs';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import { getLogger } from './logger.js';

const logger = getLogger();
const sqsClient = new SQSClient();
const REGION = process.env.AWS_REGION;
const SECURITY_HUB_REGION = process.env.SECURITY_HUB_REGION || REGION;

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
  logger.debug('formatError', { response });
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
  logger.debug('formatResponse', { response });
  return response;
};

const sendSQSmessage = async (event) => {
  const params = {
    QueueUrl: process.env.SQS_QUEUE_URL,
    Entries: event.map((issue) => {
      const uuid = uuidv4();
      return {
        Id: uuid,
        MessageDeduplicationId: uuid,
        MessageGroupId: 'XrayPayload',
        MessageBody: JSON.stringify(issue),
      };
    }),
  };

  return await sqsClient.send(new SendMessageBatchCommand(params));
};

const axiosClient = axios.create({
  baseURL: 'https://heapanalytics.com/api',
  headers: {
    'Content-Type': 'application/json',
    accept: 'application/json',
  },
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
      event: 'send-issue-to-sqs-security-hub',
      properties: callHomePayload,
    };

    logger.info('Sending data to Heap.io, path: /track', { body });

    response = await axiosClient.post('/track', body);
  } catch (e) {
    logger.error('Failed to send data to Heap.io', { e });
  }
  // eslint-disable-next-line consistent-return
  return response;
};

export async function lambdaHandler(event) {
  logger.debug('event', { event });
  try {
    const results = await sendSQSmessage(event);
    logger.debug('sendSQSmessage results:', { results });

    try {
      const callHomePayload = {
        integration: 'xray-aws-security-hub',
        region: SECURITY_HUB_REGION,
        xray_issues_received: event.length,
        messages_sent_to_sqs: results.Successful.length,
        action: 'send-issue-to-sqs-security-hub',
        jpd_url: `https://${event[0].host_name}`,
      };
      await sendCallHomeData(callHomePayload);
      logger.info('HeapIO request has been sent.');
    } catch (e) {
      logger.warn(`Error while sending info to HeapIO. ${e}`);
    }

    return formatResponse(results);
  } catch (error) {
    return formatError(error);
  }
}
