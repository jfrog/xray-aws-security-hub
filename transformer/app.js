import { BatchImportFindingsCommand, BatchUpdateFindingsCommand, SecurityHubClient } from '@aws-sdk/client-securityhub';
import { PutCommand, DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { getLogger } from './logger.js';

const logger = getLogger();
const REGION = process.env.AWS_REGION;
const SECURITY_HUB_REGION = process.env.SECURITY_HUB_REGION || REGION;

const ddbClient = new DynamoDBClient();
const hubClient = new SecurityHubClient({ region: SECURITY_HUB_REGION });

const translateConfig = {
  convertEmptyValues: false,
  removeUndefinedValues: false,
  convertClassInstanceToMap: false,
  wrapNumbers: false,
};

const ddbDocClient = DynamoDBDocumentClient.from(ddbClient, translateConfig);

const SEVERITY_LABEL_LOOKUP = {
  low: 'LOW',
  medium: 'MEDIUM',
  high: 'HIGH',
  critical: 'CRITICAL',
};

const TYPES_LOOKUP = {
  security: 'Software and Configuration Checks/Vulnerabilities/CVE',
  license: 'Software and Configuration Checks/Licenses/Compliance',
  'operational risk': 'Software and Configuration Checks/Operational Risk',
};

const getSeverity = (severity) => ({
  Label: SEVERITY_LABEL_LOOKUP[severity.toLowerCase()] || 'INFORMATIONAL',
  Original: severity,
});

const getResources = (artifact) => ({
  Type: 'Other',
  Id: artifact.sha256,
  Details: {
    Other: {
      Name: artifact.name,
      DisplayName: artifact.display_name,
      Path: artifact.path,
      PackageType: artifact.pkg_type,
    },
  },
});

const getProductFields = (body, type) => ({
  'jfrog/xray/ViolationType': type,
  'jfrog/xray/Watch': body.watch_name,
  'jfrog/xray/Policy': body.policy_name,
});

const getVulnerablePackages = (infectedFiles) => infectedFiles.map((infectedFile) => ({
  Name: infectedFile.display_name,
  PackageManager: infectedFile.pkg_type,
}));

const getVulnerabilities = (prefix, impactedArtifact) => ({
  Id: prefix,
  VulnerablePackages: getVulnerablePackages(impactedArtifact.infected_files),
});

const getVulnerabilitiesFields = (prefix, artifact) => ({
  Vulnerabilities: [getVulnerabilities(prefix, artifact)],
});

const getCommonFields = (body, type, accountId) => ({
  AwsAccountId: accountId,
  Region: SECURITY_HUB_REGION,
  CreatedAt: body.created,
  Description: body.description,
  GeneratorId: `JFrog - Xray Policy ${body.policy_name}`,
  ProductArn: `arn:aws:securityhub:${SECURITY_HUB_REGION}:${accountId}:product/${accountId}/default`,
  SchemaVersion: '2018-10-08',
  SourceUrl: `https://${body.host_name}/ui/watchesNew/edit/${body.watch_name}?activeTab=violations`,
  Title: `${body.summary.length > 256 ? `${(body.summary).substring(0, 251)}...` : body.summary}`,
  UpdatedAt: body.created,
  CompanyName: 'jfrog',
  ProductFields: getProductFields(body, type),
  ProductName: 'xray',
});

const getResourcesFields = (prefix, artifact) => ({
  Id: `${prefix} ${artifact.sha256}`,
  Resources: [getResources(artifact)],
});

const getSeverityAndTypes = (body, type) => ({
  Severity: getSeverity(body.severity),
  Types: [TYPES_LOOKUP[type.toLowerCase()]],
});

const getFindingProviderFields = (body, type) => ({
  FindingProviderFields: getSeverityAndTypes(body, type),
});

const getIdPrefix = (body, type) => (type === 'security' && body.cve ? body.cve : body.summary);

function transformIssue(issue, accountId) {
  const type = issue.type.toLowerCase();
  logger.debug(`${type} issue`);

  return issue.impacted_artifacts.map((impactedArtifact) => {
    const prefix = getIdPrefix(issue, type);
    const vulnerabilitiesFields = type === 'security' ? getVulnerabilitiesFields(prefix, impactedArtifact) : null;
    return {
      ...getCommonFields(issue, type, accountId),
      ...getResourcesFields(prefix, impactedArtifact),
      ...getFindingProviderFields(issue, type),
      ...vulnerabilitiesFields,
    };
  });
}

const generateUpdatePayload = (existingFindingsToUpdate) => existingFindingsToUpdate.map((finding) => ({
  FindingIdentifiers: [{
    Id: finding.Id,
    ProductArn: finding.ProductArn,
  }],
  Severity: {
    Label: finding.FindingProviderFields.Severity.Label,
  },
}));

const XRAY_FINDINGS_TABLE = process.env.XRAY_FINDINGS_TABLE || `xray-findings-${REGION}`;

const writeFindingsToDB = async (findingsCollection) => {
  const promises = findingsCollection.map((finding) => {
    const params = {
      TableName: XRAY_FINDINGS_TABLE,
      Item: {
        ID: finding.Id,
        TIMESTAMP: new Date().getTime().toString(),
      },
    };
    return ddbClient.send(new PutCommand(params));
  });
  const results = await Promise.allSettled(promises);

  const resultsFulfilled = results.filter((result) => (result.status === 'fulfilled')).map((result) => result.status);
  const resultsFailed = results.filter((result) => (result.status === 'rejected')).map((result) => result.message);

  return {
    SuccessCount: resultsFulfilled.length,
    SuccessfulRecords: resultsFulfilled,
    FailedCount: resultsFailed.length,
    FailedRecords: resultsFailed,
  };
};

const queryParams = (id) => ({
  TableName: XRAY_FINDINGS_TABLE,
  ProjectionExpression: 'ID',
  KeyConditionExpression: 'ID = :id',
  Limit: 1,
  ExpressionAttributeValues: {
    ':id': { S: id },
  },
});

const verifyFindingIds = async (ids) => {
  const promises = ids.map((id) => ddbDocClient.send(new QueryCommand(queryParams(id))));
  const results = await Promise.allSettled(promises);
  return results
    .filter((result) => (result.status === 'fulfilled' && result.value.Count > 0))
    .map((result) => result.value.Items[0].ID.S);
};

const sendUpdateCommand = async (updateBody) => {
  const promises = updateBody.map((body) => hubClient.send(new BatchUpdateFindingsCommand(body)));
  const results = await Promise.allSettled(promises);
  logger.debug('Unfiltered results (promises)', { results });

  const resultsFulfilled = results.filter((result) => (result.status === 'fulfilled')).map((result) => result.value.ProcessedFindings);
  const resultsFailed = results.filter((result) => (result.status === 'rejected')).map((result) => result.value.ProcessedFindings);
  logger.debug('resultsFulfilled', { resultsFulfilled });
  logger.debug('resultsFailed', { resultsFailed });

  return {
    SuccessCount: resultsFulfilled.length,
    SuccessfulFindings: resultsFulfilled,
    FailedCount: resultsFailed.length,
    FailedFindings: resultsFailed,
  };
};

export async function lambdaHandler(event, context) {
  let response;
  logger.debug('Lambda triggered by SQS message', { event });
  try {
    const accountId = process.env.USE_DEV_ACCOUNT_ID === 'true' ? process.env.DEV_ACCOUNT_ID : context.invokedFunctionArn.split(':')[4];
    const findingsCollection = event.Records.map((sqsEvent) => {
      const issue = JSON.parse(sqsEvent.body);
      return transformIssue(issue, accountId);
    }).flat();

    logger.debug('Complete findings list', { findingsCollection });

    const completeIdsCollection = findingsCollection.map((finding) => finding.Id);
    logger.debug('Unfiltered finding IDs collection', { completeIdsCollection });

    const existingFindingIDsInDB = await verifyFindingIds(completeIdsCollection);
    logger.debug('Existing finding IDs in the DB', { existingFindingIDsInDB });

    const existingFindingsToUpdate = findingsCollection.filter((item) => existingFindingIDsInDB.includes(item.Id));
    logger.debug('Findings to update', { existingFindingsToUpdate });

    const newFindingsToImport = findingsCollection.filter((item) => !existingFindingIDsInDB.includes(item.Id));
    logger.debug('Findings to import', { newFindingsToImport });

    let hubUpdateResponse;
    if (existingFindingsToUpdate.length > 0) {
      const updateFindingsPayload = generateUpdatePayload(existingFindingsToUpdate);
      logger.debug('Update payload', { updateFindingsPayload });

      hubUpdateResponse = await sendUpdateCommand(updateFindingsPayload);
      logger.debug('Security Hub update response', { hubUpdateResponse });
    }

    let hubImportResponse;
    if (newFindingsToImport.length > 0) {
      try {
        hubImportResponse = await hubClient.send(new BatchImportFindingsCommand({ Findings: newFindingsToImport }));
        logger.debug('Security Hub import response', { hubImportResponse });
      } catch (e) {
        logger.error('Error while importing findings', { e });
        throw e;
      }
      try {
        const dbResponse = await writeFindingsToDB(newFindingsToImport);
        logger.debug('DB response', { dbResponse });
      } catch (e) {
        logger.error('Error while importing findings', { e });
        throw e;
      }
    }

    response = {
      statusCode: 200,
      body: {
        importStatus: hubImportResponse,
        updateStatus: hubUpdateResponse,
      },
    };
  } catch (err) {
    response = {
      statusCode: err.statusCode,
      body: err,
    };
  }
  return response;
}
