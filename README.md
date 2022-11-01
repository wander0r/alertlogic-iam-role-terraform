# alertlogic-iam-role-terraform
AlertLogic IAM Role translated to Terraform

Overview

AlertLogic in my experience does a poor job with Control Tower Deployments, Cross Account access and supporting AWS Default Encryption Keys.
Their main deployment is also CloudFormation.  

Therefore, for organizations that doesn't support all of the above, I've created a terraform kind of translation of all the permissions needed to conduct a "Manual Deployment" of AlertLogic to Individual AWS Accounts.

Reference: https://docs.alertlogic.com/deploy/aws-manual-pro-ent.htm?Highlight=manual%20deployments#IAMpolicyandrolesetupusingAWSCloudFormation

Usage:

1. Create a iam.tf in your Terraform repository under the AWS Account/Role you want to work with. 
2. Copy and paste and modify accordingly
3. Create additional AWS resources like sns.tf, s3.tf, sqs.tf, etc.

