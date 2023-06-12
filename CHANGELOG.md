## 1.1.3 (June 12, 2023)

* Added `PointInTimeRecoverySpecification` to DynamoDB configuration
* Fixed creating of default redundant stage (Stage, Prod) in `SecurityHubApi` resource

Issue: [#30](https://github.com/jfrog/xray-aws-security-hub/issues/30)
PR: []

## 1.1.2 (May 17, 2023)

* Fix S3 bucket name in the SAM template
* Update dependencies

Issue: [#27](https://github.com/jfrog/xray-aws-security-hub/issues/27)
PRs: [#28](https://github.com/jfrog/xray-aws-security-hub/pull/28),
[#29](https://github.com/jfrog/xray-aws-security-hub/pull/29)

## 1.1.0 (September 14, 2022)

* Add Xray payload schema validation to Event Processor lambda
* Add API Gateway throttle rate limiting to SAM template 

## 1.0.0 (July 26, 2022)

* Initial release
