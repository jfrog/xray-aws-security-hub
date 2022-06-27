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

function transformCommon(body, type) {
  const region = process.env.AWS_REGION;
  const accountId = process.env.AWS_ACCESS_KEY_ID;

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

  const severity = {
    Label: SEVERITY_LABEL_LOOKUP[body.severity.toLowerCase()] || 'INFORMATIONAL',
    Original: body.severity,
  };

  const productFields = (violationType) => ({
    'jfrog/xray/ViolationType': violationType,
    'jfrog/xray/Watch': body.watch_name,
    'jfrog/xray/Policy': body.policy_name,
  });

  const vulnerablePackages = (infectedFiles) => infectedFiles.map((infectedFile) => ({
    Name: infectedFile.display_name,
    PackageManager: infectedFile.pkg_type,
  }));

  const vulnerabilities = (impactedArtifact) => ({
    Id: body.cve,
    VulnerablePackages: vulnerablePackages(impactedArtifact.infected_files),
  });

  const commonFields = {
    // Required fields
    CreatedAt: body.created,
    Description: body.description,
    GeneratorId: `JFrog - Xray Policy ${body.policy_name}`,
    ProductArn: `arn:aws:securityhub:${region}:${accountId}:product/jfrog/xray`,
    SchemaVersion: '2018-10-08',
    Severity: severity,
    SourceUrl: `<hostname>/ui/watchesNew/edit/${body.watch_name}?activeTab=violations`, // where do we get hostname? Headers?
    Title: body.summary,
    Types: 'Software and Configuration Checks/Vulnerabilities/CVE',
    UpdatedAt: body.created,
    // Optional fields
    CompanyName: 'jfrog',
    ProductFields: productFields(type),
    ProductName: 'xray',
  };

  const getArtifactFields = (cve, artifact) => ({
    Id: `${cve} ${artifact.sha256}`,
    Resources: resources(artifact),
    Vulnerabilities: vulnerabilities(artifact),
  });

  // return body.impacted_artifacts.map((artifact) => ({
  //   ...commonFields,
  //   ...getArtifactFields(body.cve, artifact),
  // }));
  //
  const results = [];
  for (const impactedArtifact of body.impacted_artifacts) {
    const artifactFields = getArtifactFields(body.cve, impactedArtifact);
    const result = {
      ...commonFields,
      ...artifactFields,
    };

    results.push(result);
  }

  return results;
}

exports.lambdaHandler = async (event) => {
  try {
    const parsedBody = JSON.parse(event.Records[0].body);
    let findings = [];
    const type = parsedBody.type.toLowerCase();
    switch (type) {
      case 'security':
        findings = transformCommon(parsedBody, type);
        break;
      case 'license':
        findings = transformCommon(parsedBody, type);
        console.log('License');
        break;
      case 'operational risk':
        findings = transformCommon(parsedBody, type);
        console.log('Operational_risk');
        break;
      default:
        console.log(`Expected type field, got: ${parsedBody.type.toLowerCase()}`);
    }
    console.log(`Body: ${JSON.stringify(parsedBody)}`);
    console.log(`Findings to send to Hub: ${JSON.stringify(findings)}`);

    for (const finding in findings) {
      console.log(`Here we send the message to Security Hub - ${finding}`);
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
};
