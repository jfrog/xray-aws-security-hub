import { SecurityHubClient, BatchImportFindingsCommand } from '@aws-sdk/client-securityhub';

const hubClient = new SecurityHubClient({});

let response;

// get the body from SQS message payload
// Split by infected_files
// Transform it to AWS sec hub format
// defferenciate based on the type - Security, License or Operational risk
// Send API call to sec hub in th eloop, one message per one array member

const SEVERITY_LABEL_LOOKUP = {
  low: 'LOW',
  medium: 'MEDIUM',
  high: 'HIGH',
  critical: 'CRITICAL',
};

const region = process.env.AWS_REGION;
const accountId = process.env.AWS_ACCESS_KEY_ID;

const severity = (body) => ({
  Label: SEVERITY_LABEL_LOOKUP[body.severity.toLowerCase()] || 'INFORMATIONAL',
  Original: body.severity,
});

const resources = (artifact) => ({
  Type: 'Other',
  Id: artifact.sha256,
  Details: [{
    Other: {
      Name: artifact.name,
      DisplayName: artifact.display_name,
      Path: artifact.path,
      PackageType: artifact.pkg_type,
    },
  }],
});

const getTypes = (type) => {
  let types;
  if (type === 'security') {
    types = 'Software and Configuration Checks/Vulnerabilities/CVE';
  } else if (type === 'license') {
    types = 'Software and Configuration Checks/Vulnerabilities';
  } else if (type === 'operational risk') {
    types = 'Software and Configuration Checks/Vulnerabilities/?';
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

const getCommonFields = (body, type) => ({
  AwsAccountId: accountId,
  CreatedAt: body.created,
  Description: body.description,
  GeneratorId: `JFrog - Xray Policy ${body.policy_name}`,
  ProductArn: `arn:aws:securityhub:${region}:${accountId}:product/jfrog/xray`,
  SchemaVersion: '2018-10-08',
  Severity: severity(body),
  SourceUrl: `<hostname>/ui/watchesNew/edit/${body.watch_name}?activeTab=violations`,
  Title: body.summary,
  Types: getTypes(type),
  UpdatedAt: body.created,
  CompanyName: 'jfrog',
  ProductFields: productFields(body, type),
  ProductName: 'xray',
});

const getVulnerabilitiesFields = (prefix, artifact) => ({
  Vulnerabilities: vulnerabilities(prefix, artifact),
});

const getResourcesFields = (prefix, artifact) => ({
  Id: `${prefix} ${artifact.sha256}`,
  Resources: resources(artifact),
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

function transformSecurity(body, type) {
  const results = [];
  for (const impactedArtifact of body.impacted_artifacts) {
    const prefix = getIdPrefix(body, type);
    const commonFields = getCommonFields(body, type);
    const resourcesFields = getResourcesFields(prefix, impactedArtifact);
    const vulnerabilitiesFields = getVulnerabilitiesFields(prefix, impactedArtifact);
    const result = {
      ...commonFields,
      ...resourcesFields,
      ...vulnerabilitiesFields,
    };

    results.push(result);
  }
  return results;
}

function transformLicense(body, type) {
  const results = [];
  for (const impactedArtifact of body.impacted_artifacts) {
    const prefix = getIdPrefix(body, type);
    const commonFields = getCommonFields(body, type);
    const resourcesFields = getResourcesFields(prefix, impactedArtifact);
    const vulnerabilitiesFields = getVulnerabilitiesFields(prefix, impactedArtifact);
    const result = {
      ...commonFields,
      ...resourcesFields,
      ...vulnerabilitiesFields,
    };

    results.push(result);
  }
  return results;
}

function transformOpRisk(body, type) {
  const results = [];
  for (const impactedArtifact of body.impacted_artifacts) {
    const prefix = getIdPrefix(body, type);
    const commonFields = getCommonFields(body, type);
    const resourcesFields = getResourcesFields(prefix, impactedArtifact);
    const result = {
      ...commonFields,
      ...resourcesFields,
    };

    results.push(result);
  }
  return results;
}

const sendIssueToHub = async (finding) => await hubClient.send(new BatchImportFindingsCommand(JSON.parse(finding)));

export async function lambdaHandler(event) {
  try {
    const parsedBody = JSON.parse(event.Records[0].body);
    let findings = [];
    const type = parsedBody.type.toLowerCase();
    switch (type) {
      case 'security':
        findings = transformSecurity(parsedBody, type);
        console.log('Security');
        break;
      case 'license':
        findings = transformLicense(parsedBody, type);
        console.log('License');
        break;
      case 'operational risk':
        findings = transformOpRisk(parsedBody, type);
        console.log('Operational_risk');
        break;
      default:
        console.log(`Expected type field, got: ${parsedBody.type.toLowerCase()}`);
    }
    console.log(`Body: ${JSON.stringify(parsedBody)}`);
    console.log(`Findings to send to Hub: ${JSON.stringify(findings)}`);

    for (const finding in findings) {
      // Query DynamoDB and see if Xray issue already exists. Import if not, otherwise Update.
      console.log(`Here we send the message to Security Hub - ${finding}`);
      // check if await will work here
      const hubResponse = await sendIssueToHub(finding);
      // const hubResponse = hubClient.send(new BatchImportFindingsCommand(JSON.parse(finding)));
      console.log(hubResponse);
    }

    response = {
      statusCode: 200,
      // body: event.Records[0].body,
    };
  } catch (err) {
    console.log(err);
    return err;
  }

  return response;
}
