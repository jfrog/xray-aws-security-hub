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

const severity = (body) => ({
  Label: SEVERITY_LABEL_LOOKUP[body.severity.toLowerCase()] || 'INFORMATIONAL',
  Original: body.severity,
});

const resources = (artifact) => ({
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
    types = ['Software and Configuration Checks/Vulnerabilities'];
  } else if (type === 'operational risk') {
    types = ['Software and Configuration Checks/Vulnerabilities/?'];
  }
  return types;
};

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

const getCommonFields = (body, type, accountId, hostname) => ({
  AwsAccountId: accountId,
  Region: region,
  CreatedAt: body.created,
  Description: body.description,
  GeneratorId: `JFrog - Xray Policy ${body.policy_name}`,
  ProductArn: `arn:aws:securityhub:${region}:${accountId}:product/${accountId}/default`,
  SchemaVersion: '2018-10-08',
  SourceUrl: `${hostname}/ui/watchesNew/edit/${body.watch_name}?activeTab=violations`,
  Title: body.summary,
  UpdatedAt: body.created,
  CompanyName: 'jfrog',
  ProductFields: productFields(body, type),
  ProductName: 'xray',
});

const getVulnerabilitiesFields = (prefix, artifact) => ({
  Vulnerabilities: [vulnerabilities(prefix, artifact)],
});

const getResourcesFields = (prefix, artifact) => ({
  Id: `${prefix} ${artifact.sha256}`,
  Resources: [resources(artifact)],
});

const findingProviderFields = (body, type) => ({
  Severity: severity(body),
  Types: getTypes(type),
});

const getFindingProviderFields = (body, type) => ({
  FindingProviderFields: findingProviderFields(body, type),
});

const getIdPrefix = (body, type) => {
  let prefix;
  if (type === 'security') {
    prefix = body.cve;
  } else {
    prefix = body.summary;
  }
  return prefix;
};

function transformSecurity(body, type, accountId, hostname) {
  const results = [];
  for (const impactedArtifact of body.impacted_artifacts) {
    const prefix = getIdPrefix(body, type);
    const commonFields = getCommonFields(body, type, accountId, hostname);
    const resourcesFields = getResourcesFields(prefix, impactedArtifact);
    const findingProvider = getFindingProviderFields(body, type);
    const vulnerabilitiesFields = getVulnerabilitiesFields(prefix, impactedArtifact);
    const result = {
      ...commonFields,
      ...resourcesFields,
      ...findingProvider,
      ...vulnerabilitiesFields,
    };

    results.push(result);
  }
  return results;
}

function transformLicense(body, type, accountId, hostname) {
  const results = [];
  for (const impactedArtifact of body.impacted_artifacts) {
    const prefix = getIdPrefix(body, type);
    const commonFields = getCommonFields(body, type, accountId, hostname);
    const resourcesFields = getResourcesFields(prefix, impactedArtifact);
    const findingProvider = getFindingProviderFields(body, type);
    const vulnerabilitiesFields = getVulnerabilitiesFields(prefix, impactedArtifact);
    const result = {
      ...commonFields,
      ...resourcesFields,
      ...findingProvider,
      ...vulnerabilitiesFields,
    };

    results.push(result);
  }
  return results;
}

function transformOpRisk(body, type, accountId, hostname) {
  const results = [];
  for (const impactedArtifact of body.impacted_artifacts) {
    const prefix = getIdPrefix(body, type);
    const commonFields = getCommonFields(body, type, accountId, hostname);
    const findingProvider = getFindingProviderFields(body, type);
    const resourcesFields = getResourcesFields(prefix, impactedArtifact);
    const result = {
      ...commonFields,
      ...findingProvider,
      ...resourcesFields,
    };

    results.push(result);
  }
  return results;
}

export async function lambdaHandler(event, context) {
  try {
    let accountId = context.invokedFunctionArn.split(':')[4];
    const hostname = 'https://artifactoryinstance.com';
    if (process.env.USE_LOCAL_ID === 'true') {
      accountId = '096302395721';
    }
    const parsedBody = JSON.parse(event.Records[0].body);
    let findings = [];
    const type = parsedBody.type.toLowerCase();
    switch (type) {
      case 'security':
        findings = transformSecurity(parsedBody, type, accountId, hostname);
        console.log('Security issue');
        break;
      case 'license':
        findings = transformLicense(parsedBody, type, accountId, hostname);
        console.log('License issue');
        break;
      case 'operational risk':
        findings = transformOpRisk(parsedBody, type, accountId, hostname);
        console.log('Operational risk');
        break;
      default:
        console.log(`Expected type field, got: ${parsedBody.type.toLowerCase()}`);
    }
    console.log(`Findings to send to Hub: ${JSON.stringify(findings)}`);
    const hubResponse = await hubClient.send(new BatchImportFindingsCommand({ Findings: findings }));

    response = {
      statusCode: 200,
      body: hubResponse,
    };
  } catch (err) {
    response = {
      statusCode: err.statusCode,
      body: err,
    };
    return response;
  }
  return response;
}
