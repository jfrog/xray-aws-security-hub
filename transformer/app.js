import { SecurityHubClient, BatchImportFindingsCommand } from '@aws-sdk/client-securityhub';

const hubClient = new SecurityHubClient();
let response;

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

const getTypes = (type) => (type === 'security' ? ['Software and Configuration Checks/Vulnerabilities/CVE'] : ['Software and Configuration Checks/Vulnerabilities']);

const productFields = (body, type) => ({
  'jfrog/xray/ViolationType': type,
  'jfrog/xray/Watch': body.watch_name,
  'jfrog/xray/Policy': body.policy_name,
});

const vulnerablePackages = (infectedFiles) => infectedFiles.map((infectedFile) => ({
  Name: infectedFile.display_name,
  PackageManager: infectedFile.pkg_type,
}));

const vulnerabilities = (prefix, impactedArtifact) => ({
  Id: prefix,
  VulnerablePackages: vulnerablePackages(impactedArtifact.infected_files),
});

const getVulnerabilitiesFields = (prefix, artifact) => ({
  Vulnerabilities: [vulnerabilities(prefix, artifact)],
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
  ProductFields: productFields(body, type),
  ProductName: 'xray',
});

const getResourcesFields = (prefix, artifact) => ({
  Id: `${prefix} ${artifact.sha256}`,
  Resources: [getResources(artifact)],
});

const findingProviderFields = (body, type) => ({
  Severity: getSeverity(body.severity),
  Types: getTypes(type),
});

const getFindingProviderFields = (body, type) => ({
  FindingProviderFields: findingProviderFields(body, type),
});

const getIdPrefix = (body, type) => (type === 'security' ? body.cve : body.summary);

function transformIssue(body, type, accountId) {
  const results = [];
  for (const impactedArtifact of body.impacted_artifacts) {
    const prefix = getIdPrefix(body, type);
    const commonFields = getCommonFields(body, type, accountId);
    const resourcesFields = getResourcesFields(prefix, impactedArtifact);
    const findingProvider = getFindingProviderFields(body, type);
    if (type === 'security') {
      const vulnerabilitiesFields = getVulnerabilitiesFields(prefix, impactedArtifact);
      const result = {
        ...commonFields,
        ...resourcesFields,
        ...findingProvider,
        ...vulnerabilitiesFields,
      };
      results.push(result);
    } else {
      const result = {
        ...commonFields,
        ...findingProvider,
        ...resourcesFields,
      };
      results.push(result);
    }
  }
  return results;
}

export async function lambdaHandler(event, context) {
  try {
    const accountId = process.env.USE_DEV_ACCOUNT_ID === 'true' ? process.env.DEV_ACCOUNT_ID : context.invokedFunctionArn.split(':')[4];
    const parsedBody = JSON.parse(event.Records[0].body);
    let findings = [];
    const type = parsedBody.type.toLowerCase();
    switch (type) {
      case 'security':
        findings = transformIssue(parsedBody, type, accountId);
        console.log('Security issue');
        break;
      case 'license':
        findings = transformIssue(parsedBody, type, accountId);
        console.log('License issue');
        break;
      case 'operational risk':
        findings = transformIssue(parsedBody, type, accountId);
        console.log('Operational risk');
        break;
      default:
        console.log(`Expected type field, got: ${parsedBody.type.toLowerCase()}`);
    }
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
