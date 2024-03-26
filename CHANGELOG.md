## 1.2.3 (March 27, 2024)

* Update Finding's 'Created at' and 'Updated at' values to use Xray scan event's 'created' date time.

PR: [#32](https://github.com/jfrog/xray-aws-security-hub/pull/32)

## 1.2.2 (December 14, 2023)

* Update dependencies from security Dependabot

PRs:

[#43](https://github.com/jfrog/xray-aws-security-hub/pull/43)
[#44](https://github.com/jfrog/xray-aws-security-hub/pull/44)
[#45](https://github.com/jfrog/xray-aws-security-hub/pull/45)

## 1.2.1 (November 3, 2023)

* Update dependencies from security Dependabot

PRs:

[#22](https://github.com/jfrog/xray-aws-security-hub/pull/22)
[#23](https://github.com/jfrog/xray-aws-security-hub/pull/23)
[#24](https://github.com/jfrog/xray-aws-security-hub/pull/24)
[#25](https://github.com/jfrog/xray-aws-security-hub/pull/25)
[#26](https://github.com/jfrog/xray-aws-security-hub/pull/26)
[#34](https://github.com/jfrog/xray-aws-security-hub/pull/34)
[#35](https://github.com/jfrog/xray-aws-security-hub/pull/35)
[#36](https://github.com/jfrog/xray-aws-security-hub/pull/36)
[#37](https://github.com/jfrog/xray-aws-security-hub/pull/37)
[#38](https://github.com/jfrog/xray-aws-security-hub/pull/38)
[#39](https://github.com/jfrog/xray-aws-security-hub/pull/39)
[#40](https://github.com/jfrog/xray-aws-security-hub/pull/40)
[#41](https://github.com/jfrog/xray-aws-security-hub/pull/41)

## 1.2.0 (June 28, 2023)

* Allow users to set a name for their environment without any restrictions.
* Allow turning on/off debugging logs on any environment.
* Hide the Authorization header value in CloudWatch debug logs.
* Debug logs are disabled by default on every environment.
* Added KMS encryption for Amazon SNS with AWS-managed key.
* Added missing retention policy attribute in DynamoDB configuration.
* Improved logging.

PR: [#32](https://github.com/jfrog/xray-aws-security-hub/pull/32)

## 1.1.3 (June 12, 2023)

* Added `PointInTimeRecoverySpecification` to DynamoDB configuration.
* Fixed creating of default redundant stage (Stage, Prod) in `SecurityHubApi` resource.

Issue: [#30](https://github.com/jfrog/xray-aws-security-hub/issues/30)
PR: [#31](https://github.com/jfrog/xray-aws-security-hub/pull/31)

## 1.1.2 (May 17, 2023)

* Fix S3 bucket name in the SAM template
* Update dependencies

Issue: [#27](https://github.com/jfrog/xray-aws-security-hub/issues/27)
PRs: [#28](https://github.com/jfrog/xray-aws-security-hub/pull/28),
[#29](https://github.com/jfrog/xray-aws-security-hub/pull/29)

## 1.1.0 (September 14, 2022)

* Add Xray payload schema validation to Event Processor lambda.
* Add API Gateway throttle rate limiting to SAM template. 

## 1.0.0 (July 26, 2022)

* Initial release
