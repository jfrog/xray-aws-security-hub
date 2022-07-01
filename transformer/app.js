import { SecurityHubClient, BatchImportFindingsCommand } from '@aws-sdk/client-securityhub';

const hubClient = new SecurityHubClient();

const SEVERITY_LABEL_LOOKUP = {
  low: 'LOW',
  medium: 'MEDIUM',
  high: 'HIGH',
  critical: 'CRITICAL',
};

const region = process.env.AWS_REGION;

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

const getTypes = (type) => {
  let types;
  if (type === 'security') {
    types = ['Software and Configuration Checks/Vulnerabilities/CVE'];
  } else if (type === 'license') {
    types = ['Software and Configuration Checks/Licenses/Compliance'];
  } else if (type === 'operational risk') {
    types = ['Software and Configuration Checks/Operational Risk'];
  }
  return types;
};

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
  Region: region,
  CreatedAt: body.created,
  Description: body.description,
  GeneratorId: `JFrog - Xray Policy ${body.policy_name}`,
  ProductArn: `arn:aws:securityhub:${region}:${accountId}:product/${accountId}/default`,
  SchemaVersion: '2018-10-08',
  SourceUrl: `https://${body.host_name}/ui/watchesNew/edit/${body.watch_name}?activeTab=violations`,
  Title: body.summary,
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
  Types: getTypes(type),
});

const getFindingProviderFields = (body, type) => ({
  FindingProviderFields: getSeverityAndTypes(body, type),
});

const getIdPrefix = (body, type) => (type === 'security' ? body.cve : body.summary);

function transformIssue(body, type, accountId) {
  return body.impacted_artifacts.map((impactedArtifact) => {
    let result;
    const prefix = getIdPrefix(body, type);
    if (type === 'security') {
      console.log(`${type} issue`);
      result = {
        ...getCommonFields(body, type, accountId),
        ...getResourcesFields(prefix, impactedArtifact),
        ...getFindingProviderFields(body, type),
        ...getVulnerabilitiesFields(prefix, impactedArtifact),
      };
    } else {
      console.log(`${type} issue`);
      result = {
        ...getCommonFields(body, type, accountId),
        ...getResourcesFields(prefix, impactedArtifact),
        ...getFindingProviderFields(body, type),
      };
    }
    return result;
  });
}

export async function lambdaHandler(event, context) {
  let response;
  try {
    const accountId = process.env.USE_DEV_ACCOUNT_ID === 'true' ? process.env.DEV_ACCOUNT_ID : context.invokedFunctionArn.split(':')[4];
    const parsedBody = JSON.parse(event.Records[0].body);
    let findings = [];
    const type = parsedBody.type.toLowerCase();
    findings = transformIssue(parsedBody, type, accountId);
    console.log(`Findings to send to Hub: ${JSON.stringify(findings)}`);
    const hubResponse = await hubClient.send(new BatchImportFindingsCommand({ Findings: findings }));
    console.log(`Security Hub response: ${JSON.stringify(hubResponse)}`);

    response = {
      statusCode: 200,
      body: hubResponse,
    };
  } catch (err) {
    response = {
      statusCode: err.statusCode,
      body: err,
    };
  }
  return response;
}
