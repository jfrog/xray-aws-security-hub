# Xray AWS Security Hub Integration

This application listens for JFrog Xray event, transforms Xray issues into security findings, and sends them to AWS Security Hub.

The following parameters can be customized for your need:
- **SecurityHubRegion** - a required field for the region where Security Hub is enabled. It will be used to import and update findings.
- **ApiAuthToken** - a required field for providing additional security between Xray and this application. The value will be stored in Secret Manager and used to verify Xray webhook requests. This value needs to be set as custom HTTP Authorization header in Xray webhook (see below).
- **DeploymentEnvironment** - an optional field to specify deployment environment (e.g. dev, stage, or prod). Default to 'prod'. 'dev' should only be used for development purpose and will enable additional logging to CloudWatch.
- **NotificationEmail** - an optional field for email address. When set, an alert email notification will be sent to this address when the Xray Dead Letter Queue has more than 10 messages.

**These parameters cannot be changed after this application is deployed**

This application must be installed in the same AWS region as the Security Hub. If you have enabled Security Hub in multiple regions, you will need to install this application in each of these regions.

## Setup Xray webhook

After deploying this application, a Xray webhook must be setup before events will be sent to this application.

Follow the [Xray webhook instructions](https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray#ConfiguringXray-ConfiguringWebhooks) and create a new webhook.

For the `URL` field, uses the `ApiEndpoint` output from this application deployment, e.g. `https://<id>.execute-api.<region>.amazonaws.com/<DeploymentEnvironment>/`

Custom headers to be configured:
- Hostname (required) - Name: `Hostname`, Value: `<JFrog instance hostname>`, e.g. `http://<instance name>.jfrog.io`
- Authorization (optional) - Name: `Authorization`, Value: `<ApiAuthToken> parameter`
